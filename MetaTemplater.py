import argparse
import collections
import copy
import json
import os
import pprint
import re
import statistics

import commonFunctions
# import RoutePolicy


def MisMatchScore(block1, block2, paramValueMap, GetLineSequence, MinimumWeightBipartiteMatching, noOfAttributes):
    """ Calculates the score and mapping of lines for matching block1 with block2.
    
    :ivar block1: The metaTemplate block from previous iteration.
    :ivar block2: The block from the new device.
    :ivar paramValueMap: The map from parameter to its values across all devices.
    :ivar GetLineSequence: Function to return the line sequence for a given block.
    :ivar minimumWeightBipartiteMatching: Function to implement the minimum weight bipartite matching for the two input blocks and 
                                          returns the mapping of lines between the two blocks.
    """
    if block1.action["type"] != block2.action["type"]:
        return commonFunctions.INFINITY, []
    else:
        LS1 = GetLineSequence(block1)
        LS2 = GetLineSequence(block2)
        score, matching = MinimumWeightBipartiteMatching(
            LS1, LS2, paramValueMap, noOfAttributes)
        return score, matching


def AlignSequences(bs1, bs2, parametersLines, **functions):
    """ Sequence Alignment of two segments.
    Based on : https://www.geeksforgeeks.org/sequence-alignment-problem/

    :ivar bs1: Block Sequence 1.
    :ivar bs2: Block Sequence 2.
    :ivar parametersLines: The ParametersLinesMap object.
    """
    m = len(bs1.blocks)
    n = len(bs2.blocks)

    dp = list()
    #
    for _ in range(m+1):
        tmp = list()
        for _ in range(n+1):
            tmp.append(commonFunctions.matrixCell())
        dp.append(tmp)

    for i in range(m+1):
        if i > 0:
            block = bs1.blocks[i-1]
            dp[i][0].score = dp[i-1][0].score + functions["GapPenalty"](block)
            dp[i][0].pointer = [0]

    for i in range(n+1):
        if i > 0:
            block = bs2.blocks[i-1]
            dp[0][i].score = dp[0][i-1].score + functions["GapPenalty"](block)
            dp[0][i].pointer = [0]

    paramValueMap = parametersLines.parameterDistribution()

    for i in range(1, m+1):
        for j in range(1, n+1):
            pairScore, matchedPairs = MisMatchScore(
                bs1.blocks[i-1], bs2.blocks[j-1], paramValueMap, functions["GetLineSequence"], functions["MinimumWeightBipartiteMatching"], functions["NumberOfAttributes"])
            block1Gap = functions["GapPenalty"](bs1.blocks[i-1])
            block2Gap = functions["GapPenalty"](bs2.blocks[j-1])

            # When scores are same preference is given to diagonal (x==y) rather than a gap (x==_)
            if dp[i-1][j-1].score + pairScore <= dp[i-1][j].score + block1Gap:
                if dp[i-1][j-1].score + pairScore <= dp[i][j-1].score + block2Gap:
                    dp[i][j].score = dp[i-1][j-1].score + pairScore
                    dp[i][j].pointer = [1]
                    dp[i][j].matchedLines = matchedPairs
                else:
                    dp[i][j].score = dp[i][j-1].score + block2Gap
                    dp[i][j].pointer = [2]
            else:
                if dp[i-1][j].score + block1Gap <= dp[i][j-1].score + block2Gap:
                    dp[i][j].score = dp[i-1][j].score + block1Gap
                    dp[i][j].pointer = [3]
                else:
                    dp[i][j].score = dp[i][j-1].score + block2Gap
                    dp[i][j].pointer = [2]
    l = m+n
    i = m
    j = n
    xpos = l
    ypos = l
    block1Alignment = list()
    block2Alignment = list()
    lineMatchings = list()
    while (not (i == 0 or j == 0)):
        if dp[i][j].pointer == [1]:
            block1Alignment.append(bs1.blocks[i-1])
            block2Alignment.append(bs2.blocks[j-1])
            lineMatchings.append(dp[i][j].matchedLines)
            i -= 1
            j -= 1
        elif dp[i][j].pointer == [2]:
            block1Alignment.append([])
            block2Alignment.append(bs2.blocks[j-1])
            j -= 1
        elif dp[i][j].pointer == [3]:
            block1Alignment.append(bs1.blocks[i-1])
            block2Alignment.append([])
            i -= 1
        else:
            raise ValueError("Undefined pointer type")
        xpos -= 1
        ypos -= 1

    while xpos >= 0:
        if i > 0:
            block1Alignment.append(bs1.blocks[i-1])
            i -= 1
        else:
            block1Alignment.append([])
        xpos -= 1

    while ypos >= 0:
        if j > 0:
            block2Alignment.append(bs2.blocks[j-1])
            j -= 1
        else:
            block2Alignment.append([])
        ypos -= 1

    block1Alignment.reverse()
    block2Alignment.reverse()
    lineMatchings.reverse()
    return block1Alignment, block2Alignment, lineMatchings


def StructuredGeneralization(patternString, devicesInfo, GetBlockSequence, outputDirectory, foundDevices, emptyDefDevices, **functions):
    """ Structured Generalization algorithm to generate the metaTemplate of the input segments.
    Based on : Algorithm 1 in the paper.

    :ivar patternString: The name pattern of the segment.
    :ivar devicesInfo: The parsed representation of the device configurations.
    :ivar GetBlockSequence: Function from a segment to a list of blocks.
    :ivar outputDirectory: The directory to output the metaTemplate.
    :ivar foundDevices: The set of devices which have at least one segment name matching the given pattern.
    :ivar emptyDefDevices: The set of devices which have a segment matching the pattern but the parser version has empty definition.
    :ivar functions: All the other functions required for templating.
    """
    pattern = re.compile(patternString)
    lineCountMap = {}
    exactDefMatchMap = {}

    # Generate the blockSequences for all devices having a segment name matching the patternString.
    for device in devicesInfo:
        segments, lineCounts = GetBlockSequence(
            device, devicesInfo[device], pattern, foundDevices, emptyDefDevices, exactDefMatchMap)
        for s, l in zip(segments, lineCounts):
            lineCountMap.setdefault(l, list()).append(s)

    # Heuristic for picking the segments: Sort the segments based on frequency and start templating with the highest frequency.
    numberofSegmentsLineCountTuples = [
        (len(lineCountMap[c]), c) for c in lineCountMap]
    numberofSegmentsLineCountTuples.sort(reverse=True)

    metaTemplate = None
    parametersLines = None
    templatingCount = 0

    #Iterate over the sorted segments and combine them one after with other.
    for _, lineCount in numberofSegmentsLineCountTuples:
        for segment in lineCountMap[lineCount]:
            if not parametersLines:
                #Initialization metaTemplate with Segment1 and store other bookkeeping info
                metaTemplate = copy.deepcopy(segment)
                metaTemplate.deviceName = "Template"
                lineMapping = {}
                lineMapping[segment.deviceName] = [
                    y for y in range(lineCount+1)]
                parametersLines = commonFunctions.ParametersLinesMap(
                    {segment.deviceName: {}}, lineMapping)
            else:
                parametersLines.parameters[segment.deviceName] = {}
                block1Alignment, block2Alignment, lineMatchings = AlignSequences(
                    metaTemplate, segment, parametersLines, **functions)
                metaTemplate.blocks = functions["GenerateTemplate"](
                    block1Alignment, block2Alignment, lineMatchings, parametersLines, segment.deviceName, functions["NumberOfAttributes"])
                templatingCount += 1

    #Minimize Parameters
    if metaTemplate:
        functions["MinimizeParameters"](metaTemplate, parametersLines, functions["NumberOfAttributes"])
        exactGroupSizes = parametersLines.addExactRouters(exactDefMatchMap)
        output, singleParamQ, spuriousQ = functions["PrintTemplate"](metaTemplate, parametersLines,
                                   outputDirectory, patternString, functions["NumberOfAttributes"])
        if output:
            finalPath = outputDirectory + os.path.sep + patternString
            with open(finalPath + os.path.sep + "output.txt", "w") as write_file:
                write_file.write(output)
            print("Please have a look at {} folder for all the data files".format(finalPath))
            return parametersLines.groupsList, singleParamQ, spuriousQ, "Inconsistent", exactGroupSizes
        else:
            print("Skipping " + patternString + " as it is consistent")
            if templatingCount == 0:
                return None, None, None,  "Exact Consistency", exactGroupSizes
            else:
                if parametersLines.counter == 0 :
                    return None, None, None,  "Reorder Consistency", exactGroupSizes
                return None, None, None,  "Consistent", exactGroupSizes
    else:
        print("Could not template for " +
              patternString + " as no non-empty segment is found")
        return None, None, None, "NotFound", None
