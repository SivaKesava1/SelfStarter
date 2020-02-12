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
import PrefixList

LINE_PENALTY = 40
ATTRIBUTES = 20
LINENUM = -1  # Line number attribute id in a line


class Block:
    """ Class to represent information about a IPV4 ACL block.

    :ivar lineNum: The line number in the sequence of blocks.
    :ivar blockJson: The representation of a parsed block  in JSON. 
    :ivar action: Whether its a permit or deny block.
    """

    def __init__(self, lineNum, action, blockJson):
        self.action = {}
        # Action doesn't have lineNum for ACLs.
        self.action["type"] = action
        self.lines = list()
        for line in blockJson:
            line[LINENUM] = lineNum[0]
            lineNum[0] += 1
            self.lines.append(line)


class ACL:
    """ The ACL Class - Defined in a generic way to fit the StructuredGeneralization but it always has one block. """

    def __init__(self, aclName, device, ACLJson, configurationFormat):
        """
        :param ACLJson: Parsed Batfish JSON representation of the ACL
        :param routerName: the router in which this ACL was found
        :param ACLName: the ACL name
        :param configurationFormat: The vendor specific format language
        """
        self.name = aclName
        self.deviceName = device
        self.blocks = list()
        self.configurationFormat = configurationFormat
        self.createBlocks(ACLJson)

    def getSrcOrDstIps(self, headerSpace, IPtype):
        ips = ["0.0.0.0/0"]
        if headerSpace[IPtype]:
                if "IpWildcardIpSpace" in headerSpace[IPtype]['class']:
                    ips = [headerSpace[IPtype]["ipWildcard"]]
                elif "PrefixIpSpace" in headerSpace[IPtype]['class']:
                    ips = [headerSpace[IPtype]["prefix"]]
                elif "AclIpSpace" in headerSpace[IPtype]['class']:
                    ips = []
                    for dstLine in headerSpace[IPtype]["lines"]:
                        if "PERMIT" != dstLine["action"]:
                            print(
                                "Unhandled ACTION mismatch in Juniper ACL {} for {}".format(self.name, self.deviceName))
                            raise NotImplementedError
                        else:
                            ips.append(dstLine["ipSpace"]["ipWildcard"])
                elif "UniverseIpSpace" in headerSpace[IPtype]["class"]:
                    ips = ["0.0.0.0/0"]
                elif "IpIpSpace" in headerSpace[IPtype]["class"]:
                    ips = [headerSpace[IPtype]["ip"]+"/32"]
                else:
                    print("Unknown {} format: ACL {} for {}".format(
                        IPtype, self.name, self.deviceName))
                    raise NotImplementedError
        return ips

    def updatePorts(self, headerSpace, srcPorts, dstPorts):
        if len(headerSpace["dstPorts"]):
            if len(dstPorts):
                raise TypeError
            else:
                dstPorts = headerSpace["dstPorts"]
        if len(headerSpace["srcPorts"]):
            if len(srcPorts):
                raise TypeError
            else:
                srcPorts = headerSpace["srcPorts"]
        return srcPorts, dstPorts

    def processACLDisjunctsConjuncts(self, entities, protocols, srcIps, dstIps, srcPorts, dstPorts):
        for entity in entities:
            if "disjuncts" in entity:
                protocols, srcIps, dstIps, srcPorts, dstPorts = self.processACLDisjunctsConjuncts(
                    entity["disjuncts"], protocols, srcIps, dstIps, srcPorts, dstPorts)
            elif "conjuncts" in entity:
                protocols, srcIps, dstIps, srcPorts, dstPorts = self.processACLDisjunctsConjuncts(
                    entity["conjuncts"], protocols, srcIps, dstIps, srcPorts, dstPorts)
            elif "headerSpace" in entity:
                srcPorts, dstPorts = self.updatePorts(
                    entity["headerSpace"], srcPorts, dstPorts)
                tmp = self.getSrcOrDstIps(entity["headerSpace"], "srcIps")
                if tmp != ["0.0.0.0/0"]:
                    srcIps.extend(tmp)
                tmp = self.getSrcOrDstIps(entity["headerSpace"], "dstIps")
                if tmp != ["0.0.0.0/0"]:
                    srcIps.extend(tmp)
                if len(entity["headerSpace"]["ipProtocols"]) > 0:
                    protocols = entity["headerSpace"]["ipProtocols"]
            elif "FalseExpr" in entity["class"] or "TrueExpr" in entity["class"]:
                pass
            else:
                raise NotImplementedError
        return protocols, srcIps, dstIps, srcPorts, dstPorts

    def createBlocks(self, ACLJson):
        presentAction = None
        block = list()
        startingLineNumber = 0
        count = 0
        for idx, line in enumerate(ACLJson['lines']):
            if not presentAction:
                presentAction = line['action']
            elif presentAction != line['action']:
                self.blocks.append(
                    Block([startingLineNumber], presentAction, block))
                block = list()
                presentAction = line['action']
                startingLineNumber = count

            if "headerSpace" in line["matchCondition"]:
                headerSpace = line["matchCondition"]["headerSpace"]
                if len(headerSpace["ipProtocols"]) > 0:
                    protocols = headerSpace["ipProtocols"]
                else:
                    protocols = ["ip"]
                srcIps = self.getSrcOrDstIps(headerSpace, "srcIps")
                dstIps = self.getSrcOrDstIps(headerSpace, "dstIps")
                dstPorts = headerSpace.get("dstPorts")
                srcPorts = headerSpace.get("srcPorts")
            elif "conjuncts" in line["matchCondition"]:
                # First conjunct would have the protocol, srcIp, dstIp (Cisco nxos) and the next ones would have the ports
                protocols, srcIps, dstIps, srcPorts, dstPorts = self.processACLDisjunctsConjuncts(
                    line["matchCondition"]["conjuncts"], [], [], [], [], [])
                if not len(protocols):
                    protocols = ["ip"]
                if not len(srcIps):
                    srcIps = ["0.0.0.0/0"]
                if not len(dstIps):
                    dstIps = ["0.0.0.0/0"]
            else:
                print("Unhandled ACL Json model - ACL: {} for {}".format(
                      self.name, self.deviceName))
                raise NotImplementedError
            for protocol in protocols:
                for srcPrefix in srcIps:
                    srcIp, srcMask = self.getIpAndMask(srcPrefix)
                    for dstPrefix in dstIps:
                        dstIp, dstMask = self.getIpAndMask(dstPrefix)
                        if len(dstPorts):
                            if len(srcPorts):
                                for dstPort in dstPorts:
                                    for srcPort in srcPorts:
                                        block.append(self.getLine(
                                            protocol, srcIp, srcMask, dstIp, dstMask, srcPort, dstPort))
                                        count += 1
                            else:
                                for dstPort in dstPorts:
                                    block.append(self.getLine(
                                        protocol, srcIp, srcMask, dstIp, dstMask, None, dstPort))
                                    count += 1
                        elif len(srcPorts):
                            for srcPort in srcPorts:
                                block.append(self.getLine(
                                    protocol, srcIp, srcMask, dstIp, dstMask, srcPort, None))
                                count += 1
                        else:
                            block.append(self.getLine(
                                protocol, srcIp, srcMask, dstIp, dstMask, None, None))
                            count += 1
        self.blocks.append(Block([startingLineNumber], presentAction, block))

    def getIpAndMask(self, prefix):
        if prefix == "0.0.0.0/0":
            ip = "0.0.0.0"
            mask = "255.255.255.255"
        elif "/" in prefix:
            ip = prefix.split("/")[0]
            mask = self.convertToMask(prefix.split("/")[1])
        elif re.match(r'\d+.\d+.\d+.\d+$', prefix):
            ip = prefix
            mask = "0.0.0.0"
        elif prefix == "172.20.0.0:0.0.235.255":
            ip = "172.20.0.0"
            mask = "0.0.255.255"
        else:
            print(
                "IP and Mask Syntax error- ACL: {} for {}".format(self.name, self.deviceName))
            raise ValueError
        return ip, mask

    def convertToMask(self, mask):
        """  
        type (int) -> str
        Converts a source or destination mask from integer to wildcard notation (inverse mask)
        Ex: 26 -> 0.0.0.63
        """
        try:
            value = int(mask)
            other = 32-value
            seq = ""
            while(value > 0):
                seq += "0"
                value -= 1
            while(other > 0):
                seq += "1"
                other -= 1
            firstoctet = str(int(seq[0:8], 2))
            secondoctet = str(int(seq[8:16], 2))
            thirdoctet = str(int(seq[16:24], 2))
            fourthoctet = str(int(seq[24:32], 2))
            return firstoctet + "."+secondoctet+"."+thirdoctet+"."+fourthoctet
        except:
            return mask

    def getLine(self, protocol, srcIp, srcMask, dstIp, dstMask, srcPort, dstPort):
        """ 
        Returns the acl line with fields separated as a dict.
        Representation based on batfish parser
        Attributes:
                        -2    : protocol
                        -1    : LineNumber
                        0-3   : srcIp
                        4-7   : srcMask
                        8-11  : dstIp
                        12-15 : dstMask
                        16-17 : srcPort
                        18-19 : dstPort
        """
        line = {}
        line[-2] = protocol
        i = 0
        for octet in srcIp.split("."):
            line[i] = octet
            i += 1
        for octet in srcMask.split("."):
            line[i] = octet
            i += 1
        for octet in dstIp.split("."):
            line[i] = octet
            i += 1
        for octet in dstMask.split("."):
            line[i] = octet
            i += 1
        if srcPort:
            line[i], line[i+1] = srcPort.split("-")
        else:
            line[i] = line[i+1] = "-1"
        i += 2
        if dstPort:
            line[i], line[i+1] = dstPort.split("-")
        else:
            line[i] = line[i+1] = "-1"
        return line


def GetBlockSequence(device, deviceInfo, pattern, foundDevices, emptyDefDevices, exactDefMatchMap):
    """ Generates block sequence for ACL from the parsed JSON object.
    
    :ivar device: The name of the device.
    :ivar deviceInfo: The JSON model of the configuration. 
    :ivar pattern: The ACL pattern that is templated.
    :ivar foundDevices: The set of devices which have at least one ACL matching the pattern.
    :ivar emptyDefDevices: The set of devices that have an empty definition for the ACL.
    :ivar exactDefMatchMap: The bookkeeping used for exact equality optimization. 
    """
    patternMatchSegments = []
    patternMatchSegmentsLineCounts = []
    if deviceInfo.get("ipAccessLists"):
        segments = deviceInfo.get("ipAccessLists")
        for segmentName in segments:
            if pattern.match(segmentName):
                if device in foundDevices:
                    rname = device + "#" + segmentName
                else:
                    rname = device
                parsedSegment = ACL(
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
    # Return infinity if the protocols of the lines do not match
    if templateLine[-2] != deviceLine[-2]:
        return commonFunctions.INFINITY
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

    return PrefixList.BipartiteMatching(LS1, LS2, paramValueMap, noOfAttributes)


def TemplateGenerator(block1Alignment, block2Alignment, lineMatchings, parametersLines, device, noOfAttributes):
    """ Given the alignment and line matchings the function returns the merged terms."""
    return PrefixList.TemplateGenerator(block1Alignment, block2Alignment, lineMatchings, parametersLines, device, noOfAttributes)


def MinimizeParameters(metaTemplate, parametersLines, noOfAttributes):
    PrefixList.MinimizeParameters(
        metaTemplate, parametersLines, noOfAttributes)


def FormatBlock(configFormat, action, lines, linePredicateMap, patternString):
    """Produces the output meta template in Cisco IOS format for a block
    Attributes:
                -2    : protocol
                -1    : LineNumber
                0-3   : srcIp
                4-7   : srcMask
                8-11  : dstIp
                12-15 : dstMask
                16-17 : srcPort
                18-19 : dstPort
    """
    output = ""
    htmlCmds = list()
    common = "\t" + action.lower()
    for line in lines:
        tmp = {}
        tmp[0] = linePredicateMap.get(line[LINENUM])
        tmp[1] = common
        tmp[2] = line[-2].lower()
        if line[4] == line[5] == line[6] == line[7] == "255":
            tmp[3] = "any"
            tmp[4] = ""
        elif line[4] == line[5] == line[6] == line[7] == "0":
            tmp[3] = "host"
            tmp[4] = ".".join([line[0], line[1], line[2], line[3]])
        else:
            tmp[3] = ".".join([line[0], line[1], line[2], line[3]])
            tmp[4] = ".".join([line[4], line[5], line[6], line[7]])
        if line[16] == line[17] == "-1":
            tmp[5] = ""
        elif line[16] == line[17]:
            tmp[5] = " eq " + line[16]
        else:
            tmp[5] = " range " + line[16] + " " + line[17]
        if line[12] == line[13] == line[14] == line[15] == "255":
            tmp[6] = "any"
            tmp[7] = ""
        elif line[12] == line[13] == line[14] == line[15] == "0":
            tmp[6] = "host"
            tmp[7] = ".".join([line[8], line[9], line[10], line[11]])
        else:
            tmp[6] = ".".join([line[8], line[9], line[10], line[11]])
            tmp[7] = ".".join([line[12], line[13], line[14], line[15]])
        if line[18] == line[19] == "-1":
            tmp[8] = ""
        elif line[18] == line[19]:
            tmp[8] = " eq " + line[18]
        else:
            tmp[8] = " range " + line[18] + " " + line[19]
        output += "{:<3}: {:<3}: {} {} {} {} {} {} {} {}\n".format(
            str(line[LINENUM]), tmp[0], tmp[1], tmp[2], tmp[3], tmp[4], tmp[5], tmp[6], tmp[7], tmp[8])
        htmlCmds.append(tmp)
    return output, htmlCmds


def PrintTemplate(metaTemplate, parametersLines, outputDirectory, patternString, noOfAttributes):
    return PrefixList.PrintTemplate(metaTemplate, parametersLines, outputDirectory, patternString, noOfAttributes)
