import collections
import json
import os
import re
import time
from datetime import datetime, timedelta
from os import listdir, makedirs, path, walk

import pandas as pd
from docopt import docopt
from pybatfish.client.commands import *
from pybatfish.question import bfq
from pybatfish.question.question import list_questions, load_questions

import ACL
import PrefixList
import RoutePolicy
from commonFunctions import createFolder
from MetaTemplater import StructuredGeneralization

doc = """
SelfStarter  automatically  infers  likely network configuration errors,
without  requiring  a  formal  specification  and  working directly with 
existing network configuration files. Given the configuration files of a 
role, SelfStarter can infer a set of parameterized templates for complex 
configuration  segments such as ACLs, prefix lists and route policies by
modeling  the  (likely)  intentional  differences as variations within a 
template while modeling the (likely) erroneous differences as variations
across  templates  and  uses  the  templates  to  propose   high-quality 
configuration outliers.

Usage: 
    main.py (--directory=<dir> | --network=<net> --snapshot=<snap>) [-harp] [--pattern=<pa>] [--nodeRegex=<nr>] [--outputDir=<dir>]
    main.py statistics [--inputDir=<idir>]

Options:
    -h --help           Show this help screen.
    -a --acl            Include ACLs.
    -r --routemap       Include RouteMaps.
    -p --prefixlist     Include PrefixLists.
    --pattern=<pa>      Segment Name Regex [default: .*].
    --nodeRegex=<nr>    Regular expression for names of nodes to include [default: .*].
    --outputDir=<dir>   The output directory [default: Results].
    --inputDir=<idir>   The top-level input directory for statistics [default: Results].

"""

prefixListFunctions = {}
prefixListFunctions["GapPenalty"] = PrefixList.GapPenalty
prefixListFunctions["GetBlockSequence"] = PrefixList.GetBlockSequence
prefixListFunctions["GetLineSequence"] = PrefixList.LineSequence
prefixListFunctions["MinimumWeightBipartiteMatching"] = PrefixList.BipartiteMatching
prefixListFunctions["GenerateTemplate"] = PrefixList.TemplateGenerator
prefixListFunctions["MinimizeParameters"] = PrefixList.MinimizeParameters
prefixListFunctions["PrintTemplate"] = PrefixList.PrintTemplate
prefixListFunctions["NumberOfAttributes"] = PrefixList.ATTRIBUTES


aclFunctions = {}
aclFunctions["GapPenalty"] = ACL.GapPenalty
aclFunctions["GetBlockSequence"] = ACL.GetBlockSequence
aclFunctions["GetLineSequence"] = ACL.LineSequence
aclFunctions["MinimumWeightBipartiteMatching"] = ACL.BipartiteMatching
aclFunctions["GenerateTemplate"] = ACL.TemplateGenerator
aclFunctions["MinimizeParameters"] = ACL.MinimizeParameters
aclFunctions["PrintTemplate"] = ACL.PrintTemplate
aclFunctions["NumberOfAttributes"] = ACL.ATTRIBUTES

routePolicyFunctions = {}
routePolicyFunctions["GapPenalty"] = RoutePolicy.GapPenalty
routePolicyFunctions["GetBlockSequence"] = RoutePolicy.GetBlockSequence
routePolicyFunctions["GetLineSequence"] = RoutePolicy.LineSequence
routePolicyFunctions["MinimumWeightBipartiteMatching"] = RoutePolicy.BipartiteMatching
routePolicyFunctions["GenerateTemplate"] = RoutePolicy.TemplateGenerator
routePolicyFunctions["MinimizeParameters"] = RoutePolicy.MinimizeParameters
routePolicyFunctions["PrintTemplate"] = RoutePolicy.PrintTemplate
routePolicyFunctions["NumberOfAttributes"] = None


def WriteFile(content, filename, outputPath):
    with open(outputPath + os.path.sep + filename, "w") as write_file:
        write_file.write(content)


def ReadFile(cmap, filePath):
    if os.path.isfile(filePath):
        with open(filePath, "r") as f:
            for line in f:
                if line[-1] == "\n":
                    line = line[:-1]
                if "Empty" in line or "Error" in line:
                    key = line.split(":")[0]
                    if key not in cmap:
                        cmap[key] = 0
                    cmap[key] += int(line.split(":")[1].split(",")[0])
                if "Number" in line:
                    key = line.split("=")[0]
                    if key not in cmap:
                        cmap[key] = 0
                    cmap[key] += int(line.split("=")[1])
    else:
        pass


def Statistics(rootDir, prefixMap, routeMap, aclMap):
    for root, dirs, _ in os.walk(rootDir):
        for name in dirs:
            direc = os.path.join(root, name)
            ReadFile(prefixMap, direc + os.path.sep +
                    "PrefixLists" + os.path.sep + "AllDiff.txt")
            ReadFile(routeMap, direc + os.path.sep +
                    "RoutePolicies" + os.path.sep + "AllDiff.txt")
            ReadFile(aclMap, direc + os.path.sep +
                    "ACLs" + os.path.sep + "AllDiff.txt")
            Statistics(direc, prefixMap, routeMap, aclMap)
   


def AllSegments(devicesInfo, segmentType, outputDirectory, segmentNameRegex, **functions):
    if not os.path.exists(outputDirectory):
        os.makedirs(outputDirectory)
    blockSeqFun = functions["GetBlockSequence"]
    del functions["GetBlockSequence"]
    csvgen = list()
    exactVsSelfStarter = []
    if segmentNameRegex == ".*":
        segmentNameCount = collections.defaultdict(int)
        for router in devicesInfo:
            for stype in segmentType:
                if devicesInfo[router].get(stype):
                    for segmentName in devicesInfo[router].get(stype):
                        # Ignoring the batfish generated RoutePolicies
                        if not segmentName.startswith("~"):
                            segmentNameCount[segmentName] += 1
        countSegmentMap = {}
        for name in segmentNameCount:
            countSegmentMap.setdefault(segmentNameCount[name], set()).add(name)
        keys = sorted(countSegmentMap.keys(), reverse=True)
        largestGroupSizeStatMap = {}
        differentCounts = {}
        differentCounts["Error"] = 0
        for key in keys:
            for segmentName in countSegmentMap[key]:
                try:
                    foundRouters = set()
                    emptyDefDevices = set()
                    groupsList, singleParamQ, spuriousQ, code, exactGroupSizes = StructuredGeneralization(
                        segmentName+"$", devicesInfo, blockSeqFun, outputDirectory, foundRouters, emptyDefDevices, **functions)
                    if groupsList:
                        questions = "\n\nFor Segment  " + segmentName + " \n"
                        questions += "Sizes of Groups found = " + \
                            str([len(tup[1]) for tup in groupsList])
                        questions += "\nNumber of Single Parameter outliers = " + \
                            str(singleParamQ.count('\n'))
                        questions += "\nNumber of Spurious Parameter outliers = " + \
                            str(spuriousQ.count('\n'))
                        largestGroup = len(
                            groupsList[0][1])/float(sum([len(tup[1]) for tup in groupsList]))
                        largestGroupSizeStatMap.setdefault(
                            largestGroup, list()).append(questions)
                        tmp = {}
                        tmp["Segment Name"] = segmentName
                        i = 1
                        for _, ro in groupsList:
                            tmp[i] = list(ro)
                            i += 1
                        csvgen.append(tmp)
                    if len(emptyDefDevices) > 0:
                        if "Empty Clauses- " + code not in differentCounts:
                            differentCounts["Empty Clauses- " + code] = 0
                        differentCounts["Empty Clauses- " + code] += 1
                    else:
                        if "No Empty Clauses- " + code not in differentCounts:
                            differentCounts["No Empty Clauses- " + code] = 0
                        differentCounts["No Empty Clauses- " + code] += 1
                    if exactGroupSizes and len(exactGroupSizes) > 1:
                        tmp = {}
                        tmp["Segment Name"] = segmentName
                        tmp["Exact"] = exactGroupSizes
                        tmp["Code"] = code
                        tmp["SelfStarter"] = [len(ro) for _, ro in groupsList] if groupsList else [
                            sum(exactGroupSizes)]
                        exactVsSelfStarter.append(tmp)
                except:
                    differentCounts["Error"] += 1
                    print("There was an error for " + segmentName)
        AllQuestions = ""
        for largestSizes in sorted(largestGroupSizeStatMap.keys(), reverse=True):
            for diff in largestGroupSizeStatMap[largestSizes]:
                AllQuestions += diff
        AllQuestions = json.dumps(
            differentCounts, sort_keys=True, indent=2) + AllQuestions
        createFolder(outputDirectory)
        with open(outputDirectory + path.sep + "AllDiff.txt", "w") as write_file:
            write_file.write(AllQuestions)
        print("\n Please have a look at the " +
              outputDirectory + " folder for alldifferences")
    else:
        StructuredGeneralization(segmentNameRegex, devicesInfo,
                                 blockSeqFun, outputDirectory, set(), set(), **functions)
    return csvgen, json.dumps(exactVsSelfStarter, sort_keys=True, indent=2)


if __name__ == '__main__':
    arguments = docopt(doc, version='SelfStarter 1.0')
    if arguments["--directory"]:
        bf_set_network("batfish")
        bf_init_snapshot(arguments["--directory"],
                         name="batfish", overwrite=True)
    elif arguments["--network"] and arguments["--snapshot"]:
        bf_set_network(arguments["--network"])
        bf_set_snapshot(arguments["--snapshot"])

    if not arguments["statistics"]:
        nodeRegex = arguments["--nodeRegex"]
        namePattern = arguments["--pattern"]
        load_questions()
        nodesData = bfq.viModel().answer()["answerElements"][0]
        if 'nodes' in nodesData:
            allNodesData = nodesData['nodes']
            nodeRegexPattern = re.compile(nodeRegex)
            nodesData = {}
            for router in allNodesData:
                if nodeRegexPattern.match(router):
                    nodesData[router] = allNodesData[router]
        else:
            print("No data could be retrieved")
            exit()
        if not os.path.exists(arguments["--outputDir"]):
            os.makedirs(arguments["--outputDir"])
        if arguments["--acl"]:
            csvgen, exactVsSelfStarter = AllSegments(nodesData, ["ipAccessLists"], arguments["--outputDir"] + os.path.sep + "ACLs", namePattern, **aclFunctions)
            WriteFile(exactVsSelfStarter, "ExactComp.json", arguments["--outputDir"]+ os.path.sep + "ACLs")
        if arguments["--prefixlist"]:
            csvgen, exactVsSelfStarter = AllSegments(nodesData, ["routeFilterLists", "route6FilterLists"], arguments["--outputDir"]+ os.path.sep + "PrefixLists", namePattern, **prefixListFunctions)
            WriteFile(exactVsSelfStarter, "ExactComp.json", arguments["--outputDir"] + os.path.sep + "PrefixLists")
        if arguments["--routemap"]:
            csvgen, exactVsSelfStarter = AllSegments(nodesData, ["routingPolicies"], arguments["--outputDir"] + os.path.sep + "RoutePolicies", namePattern, **routePolicyFunctions)   
            WriteFile(exactVsSelfStarter, "ExactComp.json", arguments["--outputDir"] + os.path.sep + "RoutePolicies")
    else:
        aclMap, prefixMap, routeMap = {},  {}, {}
        Statistics(arguments["--inputDir"], prefixMap, routeMap, aclMap)
        print("ACLs:")
        print(json.dumps(aclMap, sort_keys=True, indent=2))
        print("PrefixLists:")
        print(json.dumps(prefixMap, sort_keys=True, indent=2))
        print("RouteMaps:")
        print(json.dumps(routeMap, sort_keys=True, indent=2))
