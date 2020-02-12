import argparse
import collections
import copy
import json
import os
import pprint
import re
import statistics

import plotly
import plotly.graph_objs as go
from matplotlib import cm
from matplotlib.colors import rgb2hex

SPURIOUS_PARAM_THRESHOLD = 0.05
SINGLE_PARAM_THRESHOLD = 0.09
INFINITY = 10000


class ParametersLinesMap:
    """ The bookkeeping class to track which lines are present in each device and the parameter value mapping."""

    def __init__(self, parameters, lineMapping):
        self.counter = 0
        self.parameters = parameters
        self.lineMapping = lineMapping
        self.predicates = None
        self.groupsList = None

    def parameterDistribution(self):
        paramValueMap = {}
        for device in self.parameters:
            for param in self.parameters[device]:
                paramValueMap.setdefault(param, list()).append(
                    self.parameters[device][param])
        for param in paramValueMap:
            paramValueMap[param] = collections.Counter(paramValueMap[param])
        return paramValueMap

    def addParameter(self, param, value, newDevice):
        for device in self.parameters:
            if device != newDevice:
                self.parameters[device][param] = value

    def remapLineNumbers(self, oldtoNewLineMap):
        for device in self.lineMapping:
            oldList = self.lineMapping[device]
            newList = [oldtoNewLineMap[x]
                       if x in oldtoNewLineMap else x for x in oldList]
            self.lineMapping[device] = newList

    def paramCompatableSets(self):
        maxParam = self.counter
        compatableSets = {}
        for i in range(0, maxParam):
            presentParam = "P" + str(i)
            compatableSets[presentParam] = {}
            for j in range(0, maxParam):
                if i != j:
                    compatableSets[presentParam]["P"+str(j)] = 0
            for device in self.parameters:
                data = self.parameters[device]
                for param in data:
                    if param != presentParam:
                        if presentParam in data:
                            if data[presentParam] == data[param] and param in compatableSets[presentParam]:
                                    compatableSets[presentParam][param] = compatableSets[presentParam][param] + 1
                            else:
                                compatableSets[presentParam].pop(param, None)
        return compatableSets

    def commonValueParams(self):
        done = set()
        common = list()
        compatableSets = self.paramCompatableSets()
        for param in compatableSets:
            if param not in done:
                done.add(param)
                sameValueParams = list()
                sameValueParams.append(param)
                for compatableParam in sorted(compatableSets[param], key=compatableSets[param].get, reverse=True):
                    count = compatableSets[param][compatableParam]
                    if count > 0:
                        toAdd = True
                        for p in sameValueParams:
                            if p not in compatableSets[compatableParam]:
                                toAdd = False
                        if toAdd and compatableParam not in done:
                            sameValueParams.append(compatableParam)
                            done.add(compatableParam)
                if len(sameValueParams) > 1:
                    common.append(sameValueParams)
        return common

    def predicateGenerator(self, totalLines):
        groupsList = list()
        for device in self.lineMapping:
            lines = self.lineMapping[device]
            lines.sort()
            found = False
            for tuples in groupsList:
                if tuples[0] == lines:
                    found = True
                    tuples[1].add(device)
                    break
            if not found:
                routersSet = set()
                routersSet.add(device)
                groupsList.append((lines, routersSet))
        bitMap = {}
        for v in range(0, totalLines+1):
            bitMap[v] = list()
        for tuples in groupsList:
            linesPresent = tuples[0]
            linesAbsent = [x for x in range(
                0, totalLines+1) if x not in linesPresent]
            for line in linesPresent:
                bitMap[line].append(1)
            for line in linesAbsent:
                bitMap[line].append(0)
        sameTruthTable = list()
        for line in bitMap:
            found = False
            for tuples in sameTruthTable:
                if tuples[0] == bitMap[line]:
                    found = True
                    tuples[1].append(line)
            if not found:
                linesList = list()
                linesList.append(line)
                sameTruthTable.append((bitMap[line], linesList))
        allTrue = [1] * len(groupsList)
        predicates = {}
        counter = 0
        for tuples in sameTruthTable:
            if tuples[0] != allTrue:
                predicates["R"+str(counter)] = tuples[1]
                counter += 1
            else:
                predicates["A"] = tuples[1]
        self.predicates = predicates
        self.groupsList = groupsList

    def groupAndSortPredicates(self, metaTemplate):

        predicateLineMap = self.predicates
        linePredicateMap = {}
        for predicate in predicateLineMap:
            for line in predicateLineMap[predicate]:
                linePredicateMap[line] = predicate
        seqN = 0
        oldtoNewMap = {}
        newBlocks = list()
        for block in metaTemplate.blocks:
            predicateLineNTuples = list()
            for idx, line in enumerate(block.lines):
                predicateLineNTuples.append(
                    (linePredicateMap.get(line[-1]), idx))
            predicateLineNTuples.sort()
            modifiedBlockLines = list()
            for pair in predicateLineNTuples:
                modifiedBlockLines.append(block.lines[pair[1]])
                oldtoNewMap[block.lines[pair[1]][-1]] = seqN
                block.lines[pair[1]][-1] = seqN
                seqN = seqN + 1
            block.lines = modifiedBlockLines
            newBlocks.append(block)
        metaTemplate.blocks = newBlocks
        self.remapLineNumbers(oldtoNewMap)

        newPredicateLineMap = {}
        for predicate in predicateLineMap:
            predicateLines = list()
            for line in predicateLineMap[predicate]:
                predicateLines.append(oldtoNewMap[line])
            newPredicateLineMap[predicate] = predicateLines
        self.predicates = newPredicateLineMap

        groupsList = self.groupsList
        newgroupsList = list()
        for tuples in groupsList:
            newlines = [oldtoNewMap[l] for l in tuples[0]]
            newgroupsList.append((newlines, tuples[1]))
        self.groupsList = newgroupsList

    def addExactRouters(self, exactMap):
        groupSizes  = list()
        for device in exactMap:
            exactOnes = exactMap[device][0]
            groupSizes.append(len(exactOnes)+1)
            for tup in self.groupsList:
                if device in tup[1]:
                    tup[1].update(exactOnes)
                    break
            myMapping = self.lineMapping[device]
            myParams = self.parameters[device]
            for r in exactOnes:
                self.lineMapping[r] = myMapping
                self.parameters[r] = myParams
        groupSizes.sort(reverse=True)
        return groupSizes

    def formatGroups(self, outputMetaTemplate):
        groupCounter = 0
        devicesinfo = ""
        parameterTable = list()
        self.groupsList.sort(key=lambda x: len(x[1]), reverse=True)
        for lines, devices in self.groupsList:
            outputMetaTemplate += "\nGroup " + str(groupCounter) + "  :\n"
            devicesinfo += "\nGroup " + \
                str(groupCounter) + " : size :" + \
                str(len(devices)) + str(sorted(devices))
            for predicate in self.predicates:
                if all(elem in lines for elem in self.predicates[predicate]):
                    outputMetaTemplate += "\t" + predicate + " : True"
                else:
                    outputMetaTemplate += "\t" + predicate + " : False"
            newdict = {}
            newdict["Router"] = "Group " + str(groupCounter)
            parameterTable.append(newdict)
            groupCounter += 1
            for device in sorted(devices):
                newdict = {}
                newdict["Router"] = device
                newdict.update(self.parameters[device])
                parameterTable.append(newdict)
        outputMetaTemplate += "\n"
        outputMetaTemplate += devicesinfo
        paramValueMap = self.parameterDistribution()
        outputMetaTemplate += "\n\n" + json.dumps(paramValueMap, sort_keys=True, indent=2)
        return outputMetaTemplate, parameterTable

    def spuriousParamQuestions(self):
        paramsList = ["P"+str(i) for i in range(0, self.counter)]
        differences = ""
        for i in range(0, len(paramsList)):
            for j in range(i+1, len(paramsList)):
                different = set()
                same = set()
                for router in self.parameters:
                    if paramsList[i] in self.parameters[router] and \
                            paramsList[j] in self.parameters[router]:
                        if self.parameters[router][paramsList[i]] == self.parameters[router][paramsList[j]]:
                            same.add(router)
                        else:
                            different.add(router)
                if len(different) < SPURIOUS_PARAM_THRESHOLD*(len(same)+len(different)) and len(different) > 0:
                    differences += "Out of " + str(len(different)+len(same)) + " routers that have " +\
                        paramsList[i] + " and " + paramsList[j]+", " + str(len(same)) + " routers have equal values but routers" +\
                        str(different) + " have unequal values.\n"
        return differences

    def singleParamQuestions(self):
        differences = ""
        paramCountMap = {}
        for router in self.parameters:
            for param in self.parameters[router]:
                if param not in paramCountMap:
                    paramCountMap[param] = {}
                value = self.parameters[router][param]
                if value not in paramCountMap[param]:
                    paramCountMap[param][value] = (1, set())
                else:
                    paramCountMap[param][value] = (
                        paramCountMap[param][value][0]+1, paramCountMap[param][value][1])
                paramCountMap[param][value][1].add(router)

        for param in paramCountMap:
            totalCount = 0
            for value in paramCountMap[param]:
                totalCount += paramCountMap[param][value][0]
            avergae = totalCount/len(paramCountMap[param])
            for value in paramCountMap[param]:
                if paramCountMap[param][value][0] < SINGLE_PARAM_THRESHOLD*avergae:
                    differences += "Out of " + str(totalCount) + " routers that have the parameter " + param + " routers " + str(
                        paramCountMap[param][value][1]) + " have " + value + " which is in minority.\n"
        return differences


class matrixCell():
    """ A cell in the matrix for sequence alignment
    
    :ivar score : The value of that cell
    :ivar pointer: Whether this value was obtained from diagonal(1), left(2) or right(3).
                   The pointer is stored so as not to compute clauseScore multiple times. 
    :ivar matchedLines: The line mapping for the aligned blocks.
    """

    def __init__(self):
        self.score = 0
        self.pointer = [-1]
        self.matchedLines = []


def generateHTML(htmlLines, parametersLines, outputPath):

    outputLines = outputPath + os.path.sep + "MetaTemplate.html"
    outputGroups = outputPath + os.path.sep + "Groups.html"

    predList = parametersLines.predicates.keys()

    if len(predList) < 10:
        color = 'Pastel1'
    elif len(predList) < 13:
        color = 'Set3'
    else:
        color = 'tab20'
    colors = cm.get_cmap(color, len(predList))
    colors = [colors(1.*i/len(predList)) for i in range(len(predList))]
    colors = [rgb2hex(c) for c in colors]
    predToColor = dict(zip(predList, list(zip(colors, range(len(predList))))))
    header = [' ']*(len(htmlLines[0].keys())-1)
    cellsVal = [[line[(idx+1)] for line in htmlLines]
                for idx in range(len(header))]
    cellColor = [[predToColor[line[0]][0]
                  for line in htmlLines] * len(header)]
    trace1 = go.Table(
        columnwidth=[150] * len(header),
        header=dict(values=header),
        cells=dict(values=cellsVal,
                   fill=dict(color=cellColor)
                   ))
    data = [trace1]
    plotly.offline.plot(data, filename=outputLines, auto_open=False)

    white = 'rgb(255,255,255)'
    groupsList = parametersLines.groupsList
    header_gr = ['group%d(%d routers)' % (i, len(groupsList[i][1]))
                 for i in range(len(groupsList))]
    cellsVal_gr = [['']*len(predList)]*len(groupsList)
    cellColor_gr = [([white]*len(predList)) for i in range(len(groupsList))]
    orderedPredicates = []
    [orderedPredicates.append(i[0])
     for i in htmlLines if not orderedPredicates.count(i[0])]
    for i in range(len(groupsList)):
        groupPredicates = set()
        for idx in groupsList[i][0]:
            groupPredicates.add(htmlLines[idx][0])
        for idx, pred in enumerate(orderedPredicates):
            if pred in groupPredicates:
                cellColor_gr[i][idx] = predToColor[pred][0]
    trace2 = go.Table(
        columnwidth=[20] * len(header_gr),
        header=dict(values=header_gr),
        cells=dict(values=cellsVal_gr,
                   fill=dict(color=cellColor_gr)
                   )
    )
    data = [trace2]
    plotly.offline.plot(data, filename=outputGroups, auto_open=False)


def createFolder(path):
    if not os.path.exists(path):
        os.makedirs(path)


def instanceCheck(u, v):
    if isinstance(v, list) and isinstance(u, list):
        if not checkListEquality(v, u):
            return False
    elif isinstance(v, dict) and isinstance(u, dict):
        if not checkdictEquality(u, v):
            return False
    elif v != u:
        return False
    return True


def checkListEquality(json1, json2):
    if len(json1) != len(json2):
        return False
    for i, v in enumerate(json1):
        if not instanceCheck(v, json2[i]):
            return False
    return True


def checkdictEquality(json1, json2):
    keys1 = list(json1.keys())
    keys2 = list(json2.keys())
    keys1.sort()
    keys2.sort()
    if keys1 != keys2:
        return False
    else:
        for key in keys1:
            if not instanceCheck(json1[key], json2[key]):
                return False
        return True


def checkJSONEquality(exisitingMap, newJson, router):
    for r in exisitingMap:
        eJson = exisitingMap[r][1]
        if instanceCheck(eJson, newJson):
            exisitingMap[r][0].add(router)
            return True
    exisitingMap[router] = (set(), newJson)
    return False
