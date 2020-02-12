import argparse
import collections
import copy
import json
import os
import pprint
import re

import pandas as pd
import plotly
import plotly.graph_objs as go
from docopt import docopt
from matplotlib import cm
from matplotlib.colors import rgb2hex
from munkres import Munkres
from operator import itemgetter

import commonFunctions
import ACL

LINE_PENALTY = 14
ATTRIBUTES = 11
LINENUM = -1  # Line number attribute in a line


class Block:
    """ Class to represent information about a prefix-list block.

    :ivar lineNum: The line number in the sequence of blocks.
    :ivar blockJson: The representation of a parsed block  in JSON. 
    :ivar action: Whether its a permit or deny block.
    
    Representation based on batfish parser
        For example, if "ipwildcard" = 10.30.0.0/15 (2000:0:0:0:0:0:0:0/3) and "lengthRange" : 15-20 (3-128) 
        Attributes:
                        -2 - IPV4 or IPV6
                        -1 - LineNumber
                        0 - 15 (3)
                        1 - 15 (3)
                        2 - 20 (128)
                        3 - 10 (2000)
                        4 - 30 (0)
                        5 - 0  (0)
                        6 - 0  (0)
                        7 - 0  (0)..
    """

    def __init__(self, lineNum, action, blockJson):
        self.action = {}
        # Action doesn't have lineNum for prefixlists.
        self.action["type"] = action
        self.lines = list()
        for prefix in blockJson:
            line = {}
            line[LINENUM] = lineNum[0]
            lineNum[0] += 1
            line[1], line[2] = prefix["lengthRange"].split("-")
            if ":" not in prefix["ipWildcard"]:
                line[-2] = 0
                if "/" in prefix["ipWildcard"]:
                    line[0] = prefix["ipWildcard"].split("/")[1]
                else:
                    line[0] = "32"
                prefixIP = prefix["ipWildcard"].split("/")[0]
                for i, octet in enumerate(prefixIP.split(".")):
                    line[i+3] = octet
                line[7] = line[8] = line[9] = line[10] = '0'
            else:
                line[-2] = 1
                if "/" in prefix["ipWildcard"]:
                    line[0] = prefix["ipWildcard"].split("/")[1]
                else:
                    line[0] = "128"
                prefixIP = prefix["ipWildcard"].split("/")[0]
                for i, doubleOctet in enumerate(prefixIP.split(":")):
                    line[i+3] = doubleOctet
            self.lines.append(line)


class PrefixList:
    """ The Prefix-List Class - Defined in a generic way to fit the StructuredGeneralization but it always has one block. """

    def __init__(self, prefixListName, device, prefixListJson, configurationFormat):
        """
        :param prefixListJson: Parsed Batfish JSON representation of the PrefixList
        :param routerName: the router in which this Prefix-List was found
        :param prefixListName: the Prefix-List name
        :param configurationFormat: The vendor specific format language
        """
        self.name = prefixListName
        self.deviceName = device
        self.blocks = list()
        self.configurationFormat = configurationFormat
        self.createBlocks(prefixListJson)

    def createBlocks(self, prefixListJson):
        presentAction = None
        block = list()
        startingLineNumber = 0
        for idx, line in enumerate(prefixListJson['lines']):
            if not presentAction:
                presentAction = line['action']
            elif presentAction != line['action']:
                self.blocks.append(
                    Block([startingLineNumber], presentAction, block))
                block = list()
                presentAction = line['action']
                startingLineNumber = idx
            block.append(line)
        self.blocks.append(Block([startingLineNumber], presentAction, block))


def GetBlockSequence(device, deviceInfo, pattern, foundDevices, emptyDefDevices, exactDefMatchMap):
    """ Generates block sequence for prefixlist from the parsed JSON object.
    
    :ivar device: The name of the device.
    :ivar deviceInfo: The JSON model of the configuration. 
    :ivar pattern: The prefixlist pattern that is templated.
    :ivar foundDevices: The set of devices which have at least one prefixlist matching the pattern.
    :ivar emptyDefDevices: The set of devices that have an empty definition for the prefixlist.
    :ivar exactDefMatchMap: The bookkeeping used for exact equality optimization. 
    """
    patternMatchSegments = []
    patternMatchSegmentsLineCounts = []
    if deviceInfo.get("routeFilterLists"):
        # segments = {**deviceInfo.get("routeFilterLists", {}),
        #             **deviceInfo.get("route6FilterLists", {})}
        segments = deviceInfo.get("routeFilterLists")
        for segmentName in segments:
            if pattern.match(segmentName):
                if device in foundDevices:
                    rname = device + "#" + segmentName
                else:
                    rname = device
                parsedSegment = PrefixList(
                    segmentName, rname, segments[segmentName], deviceInfo['configurationFormat'])
                if len(parsedSegment.blocks) > 0 and len(parsedSegment.blocks[0].lines) > 0:
                    foundDevices.add(rname)
                    if not commonFunctions.checkJSONEquality(exactDefMatchMap, segments[segmentName], rname):
                        # Last block's last line's (-1) attribute.
                        totalLines = parsedSegment.blocks[-1].lines[-1][LINENUM]
                        patternMatchSegments.append(parsedSegment)
                        patternMatchSegmentsLineCounts.append(totalLines)
                else:
                    emptyDefDevices.add(rname)
    return patternMatchSegments, patternMatchSegmentsLineCounts


def GapPenalty(block):
    """Returns the score for matching the input block with a gap."""
    return len(block.lines)*LINE_PENALTY


def LineSequence(block):
    """Returns the line sequences for a block."""
    return block.lines


def LineScore(templateLine, deviceLine, paramValueMap):
    """Returns the score for matching the line from the metatemplate with a line from the device."""
    score = 0
    for i in range(ATTRIBUTES):
        if templateLine.get(i) and deviceLine.get(i):
            if templateLine[i] != deviceLine[i]:
                if templateLine[i] not in paramValueMap or deviceLine[i] not in paramValueMap[templateLine[i]]:
                    score += 2
                else:
                    score += 1
        else:
            score += 2
    return score


def BipartiteMatching(LS1, LS2, paramValueMap, noOfAttributes):
    """ Score and matching calculator for matching LineSequence1 with LineSequence2."""
    #Based on the number of attributes in a line pick the appropriate entities either for ACL or prefixlist
    if noOfAttributes == ATTRIBUTES:
        LineScoreFunc = LineScore
        linePenalty = LINE_PENALTY
    else:
        LineScoreFunc = ACL.LineScore
        linePenalty = ACL.LINE_PENALTY

    #Remove exactly equal Lines to speedup Munkres algorithm
    ls1HashMap = {}
    ls1Matched = set()
    ls2Matched = set()
    matched = []
    # For each line remove the lineNumber attribute
    for i, l1 in enumerate(LS1):
        ls1HashMap.setdefault(
            hash(frozenset(filter(lambda a: a[0] != LINENUM, l1.items()))), list()).append(i)
    for j, l2 in enumerate(LS2):
        hashValue = hash(frozenset(filter(lambda a: a[0] != LINENUM, l2.items())))
        matches = ls1HashMap.get(hashValue)
        if matches:
            ls1Matched.add(matches[-1])
            ls2Matched.add(j)
            matched.append((matches[-1], j))
            if len(matches) == 1:
                del ls1HashMap[hashValue]
            else:
                del ls1HashMap[hashValue][-1]

    newLS1 = []
    ls1Map = {}
    x = 0
    for i, line in enumerate(LS1):
        if i not in ls1Matched:
            ls1Map[x] = i
            newLS1.append(line)
            x += 1
    newLS2 = []
    ls2Map = {}
    x = 0
    for i, line in enumerate(LS2):
        if i not in ls2Matched:
            ls2Map[x] = i
            newLS2.append(line)
            x += 1
    similarityMatrix = []
    for tline in newLS1:
        row = []
        for dline in newLS2:
            row.append(LineScoreFunc(tline, dline, paramValueMap))
        similarityMatrix.append(row)
    indicies = []
    matchScore = 0
    if len(similarityMatrix) > 0:
        m = Munkres()
        indicies = m.compute(similarityMatrix)
        for x, y in indicies:
            if similarityMatrix[x][y] != commonFunctions.INFINITY:
                matched.append((ls1Map[x], ls2Map[y]))
                matchScore += similarityMatrix[x][y]
            else:
                matchScore += linePenalty
    matchScore += linePenalty*abs(len(LS1)-len(LS2))
    return matchScore, matched


def MergeLines(templateLines, deviceLines, lineNum, parametersLines, matching, oldtoNewLineMap, newDeviceLines, device, noOfAttributes):

    combinedLines = []
    paramValueMap = parametersLines.parameterDistribution()
    templateLeftout = []
    deviceLeftout = []
    tmp = [x for x, y in matching]
    [templateLeftout.append(i)
     for i in range(len(templateLines)) if i not in tmp]
    tmp = [y for x, y in matching]
    [deviceLeftout.append(i) for i in range(len(deviceLines)) if i not in tmp]

    for i, line in enumerate(templateLines):
        if i in templateLeftout:
            line = copy.deepcopy(line)
            oldtoNewLineMap[line[LINENUM]] = lineNum
            line[LINENUM] = lineNum
            lineNum += 1
            combinedLines.append(line)

    for i, line in enumerate(deviceLines):
        if i in deviceLeftout:
            line = copy.deepcopy(line)
            line[LINENUM] = lineNum
            newDeviceLines.append(lineNum)
            lineNum += 1
            combinedLines.append(line)

    for i, j in matching:
        tLine = templateLines[i]
        dLine = deviceLines[j]
        line = copy.deepcopy(tLine)
        for attribute in range(noOfAttributes):
            if tLine.get(attribute) and dLine.get(attribute):
                if tLine[attribute] != dLine[attribute]:
                    if tLine[attribute] not in paramValueMap:
                        param = "P" + str(parametersLines.counter)
                        parametersLines.counter += 1
                        parametersLines.parameters[device][param] = dLine[attribute]
                        parametersLines.addParameter(
                            param, tLine[attribute], device)
                        line[attribute] = param
                    else:
                        parametersLines.parameters[device][tLine[attribute]
                                                           ] = dLine[attribute]
            else:
                if dLine.get(attribute):
                    param = "P" + str(parametersLines.counter)
                    parametersLines.counter += 1
                    parametersLines.parameters[device][param] = dLine[attribute]
                    parametersLines.addParameter(param, "", device)
                    line[attribute] = param
        oldtoNewLineMap[line[LINENUM]] = lineNum
        line[LINENUM] = lineNum
        newDeviceLines.append(lineNum)
        lineNum += 1
        combinedLines.append(line)

    return combinedLines, lineNum


def TemplateGenerator(block1Alignment, block2Alignment, lineMatchings, parametersLines, device, noOfAttributes):
    """ Given the alignment and line matchings the function returns the merged terms."""

    oldtoNewLineMap = {}
    newDeviceLines = list()
    mergedBlocks = list()
    lineNum = 0
    j = 0
    if len(block1Alignment) != len(block2Alignment):
        raise ValueError("Something is wrong in alignment!!!")
    else:
        for i, v in enumerate(block1Alignment):
            if v == []:
                if block2Alignment[i] != []:
                    block = copy.deepcopy(block2Alignment[i])
                    for line in block.lines:
                        line[LINENUM] = lineNum
                        newDeviceLines.append(lineNum)
                        lineNum += 1
                    mergedBlocks.append(block)
            else:
                if block2Alignment[i] == []:
                    block = copy.deepcopy(v)
                    for line in block.lines:
                        oldtoNewLineMap[line[LINENUM]] = lineNum
                        line[LINENUM] = lineNum
                        lineNum += 1
                    mergedBlocks.append(block)
                else:
                    block = copy.deepcopy(v)
                    block.lines, lineNum = MergeLines(
                        block.lines, block2Alignment[i].lines, lineNum, parametersLines, lineMatchings[j], oldtoNewLineMap, newDeviceLines, device, noOfAttributes)
                    j += 1
                    mergedBlocks.append(block)
    parametersLines.remapLineNumbers(oldtoNewLineMap)
    parametersLines.lineMapping[device] = newDeviceLines
    return mergedBlocks


def ModifyErase(metaTemplate, parametersLines, replaceWith, eraseList, noOfAttributes):
    """ Replaces all the parameters in the eraselist with replacewith in the metatemplate."""
    for block in metaTemplate.blocks:
        for line in block.lines:
            for attribute in range(noOfAttributes):
                if line[attribute] in eraseList:
                    line[attribute] = replaceWith

    for device in parametersLines.parameters:
        value = None
        found = False
        for removals in eraseList:
            if removals in parametersLines.parameters[device]:
                found = True
                value = parametersLines.parameters[device][removals]
                parametersLines.parameters[device].pop(removals)
        if found or replaceWith in parametersLines.parameters[device]:
            parametersLines.parameters[device][replaceWith] = parametersLines.parameters[device].get(
                replaceWith, value)


def RemapParameters(metaTemplate, parametersLines, noOfAttributes):
    """Makes a pass over the metatemplate to re-number the parameters from the first line."""
    oldtoNewParamMap = {}
    count = 0
    for block in metaTemplate.blocks:
        for line in block.lines:
            for attribute in range(noOfAttributes):
                #May change to regex if required
                if line[attribute].startswith("P"):
                    if not oldtoNewParamMap.get(line[attribute]):
                        oldtoNewParamMap[line[attribute]] = "P"+str(count)
                        line[attribute] = "P"+str(count)
                        count += 1
                    else:
                        line[attribute] = oldtoNewParamMap.get(line[attribute])
    parametersLines.counter = count
    for device in parametersLines.parameters:
        newMap = {}
        for key, value in parametersLines.parameters[device].items():
            if key in oldtoNewParamMap:
                newMap[oldtoNewParamMap[key]] = value
            else:
                newMap[key] = value
        parametersLines.parameters[device] = newMap
    for device in parametersLines.lineMapping:
        parametersLines.lineMapping[device].sort()


def MinimizeParameters(metaTemplate, parametersLines, noOfAttributes):
    """ Reduces the number of parameters required by replacing different parameters with a single parameter if they agree on all devices."""

    lineParamMap = {}
    for block in metaTemplate.blocks:
        for line in block.lines:
            for attribute in range(noOfAttributes):
                if "P" in line[attribute]:
                    lineParamMap.setdefault(
                        line[LINENUM], set()).add(line[attribute])

    for device in parametersLines.lineMapping:
        myParam = set()
        for lineNumber in parametersLines.lineMapping[device]:
            if lineNumber in lineParamMap:
                myParam.update(lineParamMap.get(lineNumber))
        extraParams = set(parametersLines.parameters[device].keys()) - myParam
        [parametersLines.parameters[device].pop(
            extra, None) for extra in extraParams]

    common = parametersLines.commonValueParams()
    for x in common:
        ModifyErase(metaTemplate, parametersLines, x[0], x[1:], noOfAttributes)
    parametersLines.predicateGenerator(
        metaTemplate.blocks[-1].lines[-1][LINENUM])
    parametersLines.groupAndSortPredicates(metaTemplate)
    RemapParameters(metaTemplate, parametersLines, noOfAttributes)


def FormatBlock(configFormat, action, lines, linePredicateMap, patternString):
    """Produces the output meta template in Juniper Flat language or Cisco IOS format for a block"""
    output = ""
    htmlCmds = list()
    if "juniper" in configFormat.lower():
        common = "set policy-options prefix-list " + patternString
        for line in lines:
            tmp = {}
            tmp[0] = linePredicateMap.get(line[LINENUM])
            tmp[1] = common
            if line[-2] == 0:
                tmp[2] = ".".join(
                    [line[3], line[4], line[5], line[6]]) + "/" + line[0]
            else:
                tmp[2] = ":".join([line[3], line[4], line[5], line[6],
                                   line[7], line[8], line[9], line[10]]) + "/" + line[0]

            #Exact
            if line[0] == line[1] == line[2]:
                tmp[3] = "exact"
            elif line[0] == line[1]:
                tmp[3] = "upto /" + line[2]
            else:
                tmp[3] = "prefix-length-range /" + line[1] + "-/" + line[2]
            output += "{:<3}: {:<3}: {} {} {}\n".format(
                str(line[LINENUM]), tmp[0], tmp[1], tmp[2], tmp[3])
            htmlCmds.append(tmp)

    if "cisco" in configFormat.lower() or "arista" in configFormat.lower():
        common = " prefix-list " + patternString + " " + action + " "
        for line in lines:
            tmp = {}
            tmp[0] = linePredicateMap.get(line[LINENUM])
            tmp[1] = common
            if line[-2] == 0:
                tmp[1] = "ip" + tmp[1]
                tmp[2] = ".".join(
                    [line[3], line[4], line[5], line[6]]) + "/" + line[0]
            else:
                tmp[1] = "ipv6" + tmp[1]
                tmp[2] = ":".join([line[3], line[4], line[5], line[6],
                                   line[7], line[8], line[9], line[10]]) + "/" + line[0]
            if line[0] == line[1] == line[2]:
                tmp[3] = " "
            elif line[0] == line[1]:
                tmp[3] = "/"+line[0] + " le " + line[2]
            elif line[1] == line[2] and line[0] != line[1]:
                tmp[3] = "/"+line[0] + " eq " + line[1]
            elif line[1] == line[2]:
                tmp[3] = "/"+line[0] + " ge " + line[1]
            else:
                tmp[3] = "/"+line[0] + " ge " + line[1] + " le " + line[2]
            output += "{:<3}: {:<3}: {} {} {}\n".format(
                str(line[LINENUM]), tmp[0], tmp[1], tmp[2], tmp[3])
            htmlCmds.append(tmp)
    return output, htmlCmds


def PrintTemplate(metaTemplate, parametersLines, outputDirectory, patternString, noOfAttributes):
    """Produces the output meta template in Juniper flat language format or Cisco IOS for the prefix lists."""
    if noOfAttributes == ATTRIBUTES:
        formatBlockFunc = FormatBlock
    else:
        formatBlockFunc = ACL.FormatBlock
    linePredicateMap = {}
    for predicate in parametersLines.predicates:
        for line in parametersLines.predicates[predicate]:
            linePredicateMap[line] = predicate
    outputMetaTemplate = ""
    htmlLines = list()
    for block in metaTemplate.blocks:
        output, htmlCmds = formatBlockFunc(
            metaTemplate.configurationFormat, block.action["type"], block.lines, linePredicateMap, patternString)
        outputMetaTemplate += output
        htmlLines.extend(htmlCmds)
    outputMetaTemplate, parameterTable = parametersLines.formatGroups(
        outputMetaTemplate)
    singleParamDifferences = parametersLines.singleParamQuestions()
    spuriousParamDifferences = parametersLines.spuriousParamQuestions()

    finalPath = outputDirectory + os.path.sep + patternString
    if parametersLines.counter > 0:
        commonFunctions.createFolder(finalPath)
        # with open(finalPath + os.path.sep + "parameters.json", "w") as write_param:
        #     json.dump(parameterTable, write_param, sort_keys=True, indent=2)
        df = pd.DataFrame(parameterTable)
        df.to_csv(finalPath + os.path.sep + "parameters.csv")

    if len(parametersLines.groupsList) > 1 or singleParamDifferences != "" or spuriousParamDifferences != "":
        commonFunctions.createFolder(finalPath)
        outputMetaTemplate = "\n\nWe have found the following differences in this Segment\n" + \
            singleParamDifferences + "\n" + spuriousParamDifferences + outputMetaTemplate + "\n"
        commonFunctions.generateHTML(htmlLines, parametersLines, finalPath)
        return outputMetaTemplate, singleParamDifferences, spuriousParamDifferences
    else:
        if parametersLines.counter > 0:
            commonFunctions.createFolder(finalPath)
            with open(finalPath + os.path.sep + "output.txt", "w") as write_file:
                write_file.write(outputMetaTemplate)
            commonFunctions.generateHTML(htmlLines, parametersLines, finalPath)
        return None, None, None
