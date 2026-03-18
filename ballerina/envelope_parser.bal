// Copyright (c) 2026 WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
//
// WSO2 LLC. licenses this file to you under the Apache License,
// Version 2.0 (the "License"); you may not use this file except
// in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

import ballerina/io;

// X12 ISA segment is fixed-width. Field delimiter is always at position 3.
// Total ISA segment length is 106 characters.
const int ISA_SEGMENT_LENGTH = 106;

# Reads the X12 ISA interchange header and (if present) the GS functional-group
# header from the given EDI text without requiring a schema. This is useful for
# routing and schema selection before the full schema has been loaded.
#
# + ediText - Raw EDI text starting at or before the ISA segment
# + return - Parsed X12Headers, or Error if the ISA segment cannot be found/parsed
public isolated function x12HeadersFromEdiString(string ediText) returns X12Headers|Error {
    string trimmed = ediText.trim();
    if !trimmed.startsWith("ISA") {
        return error Error("EDI text does not start with an ISA segment.");
    }
    if trimmed.length() < ISA_SEGMENT_LENGTH {
        return error Error(string `ISA segment is too short. Expected ${ISA_SEGMENT_LENGTH} characters, found ${trimmed.length()}.`);
    }

    // ISA is fixed-width: delimiter at position 3
    string fieldDelimiter = trimmed.substring(3, 4);
    string[] parts = splitByDelimiter(trimmed.substring(0, ISA_SEGMENT_LENGTH), fieldDelimiter);
    if parts.length() < 16 {
        return error Error(string `ISA segment has fewer fields than expected. Found ${parts.length()} fields.`);
    }

    X12ISA isa = {
        authInfoQualifier: parts[1].trim(),
        authInfo: parts[2].trim(),
        securityQualifier: parts[3].trim(),
        securityInfo: parts[4].trim(),
        senderQualifier: parts[5].trim(),
        senderId: parts[6].trim(),
        receiverQualifier: parts[7].trim(),
        receiverId: parts[8].trim(),
        date: parts[9].trim(),
        time: parts[10].trim(),
        version: parts[12].trim(),
        controlNumber: parts[13].trim(),
        usageIndicator: parts[15].trim()
    };

    // The segment terminator is the last character of the ISA segment (position 105)
    string segmentTerminator = trimmed.substring(ISA_SEGMENT_LENGTH - 1, ISA_SEGMENT_LENGTH);

    // Try to find the next segment (GS)
    X12GS? gs = ();
    string afterISA = trimmed.length() > ISA_SEGMENT_LENGTH ? trimmed.substring(ISA_SEGMENT_LENGTH) : "";
    string remaining = afterISA.trim();
    if remaining.startsWith("GS") {
        int segEnd = remaining.indexOf(segmentTerminator) ?: remaining.length();
        string gsSegText = remaining.substring(0, segEnd);
        string[] gsFields = splitByDelimiter(gsSegText, fieldDelimiter);
        if gsFields.length() >= 9 {
            gs = {
                functionalIdentifier: gsFields[1].trim(),
                senderId: gsFields[2].trim(),
                receiverId: gsFields[3].trim(),
                date: gsFields[4].trim(),
                time: gsFields[5].trim(),
                controlNumber: gsFields[6].trim(),
                version: gsFields[8].trim()
            };
        }
    }
    return {isa, gs};
}

# Reads X12 interchange headers from a file without requiring a schema.
#
# + filePath - Path to the EDI file
# + return - Parsed X12Headers, or Error if the file cannot be read or ISA cannot be parsed
public isolated function x12HeadersFromFile(string filePath) returns X12Headers|Error {
    string|io:Error ediText = io:fileReadString(filePath);
    if ediText is io:Error {
        return error Error(string `Failed to read file '${filePath}': ${ediText.message()}`);
    }
    return x12HeadersFromEdiString(ediText);
}

# Reads the EDIFACT UNB interchange header and (if present) the UNH message
# header from the given EDI text without requiring a schema. Handles the optional
# UNA service string advice to determine delimiters.
#
# + ediText - Raw EDI text starting at or before the UNA/UNB segment
# + return - Parsed EdifactHeaders, or Error if UNB cannot be found/parsed
public isolated function edifactHeadersFromEdiString(string ediText) returns EdifactHeaders|Error {
    string trimmed = ediText.trim();

    // EDIFACT defaults
    string fieldDelim = "+";
    string componentDelim = ":";
    string segmentTerminator = "'";

    string remaining = trimmed;

    // Parse UNA if present
    if trimmed.startsWith("UNA") {
        if trimmed.length() < 9 {
            return error Error("UNA service string is too short.");
        }
        componentDelim = trimmed.substring(3, 4);
        fieldDelim = trimmed.substring(4, 5);
        segmentTerminator = trimmed.substring(8, 9);
        remaining = trimmed.substring(9).trim();
    }

    if !remaining.startsWith("UNB") {
        return error Error("EDI text does not contain a UNB segment after UNA (or at the start).");
    }

    // Find end of UNB segment
    int unbEnd = remaining.indexOf(segmentTerminator) ?: remaining.length();
    string unbText = remaining.substring(0, unbEnd);
    string[] unbFields = splitByDelimiter(unbText, fieldDelim);

    if unbFields.length() < 5 {
        return error Error(string `UNB segment has fewer fields than expected. Found ${unbFields.length()} fields.`);
    }

    string[] syntaxParts = splitByDelimiter(unbFields[1], componentDelim);
    string[] senderParts = splitByDelimiter(unbFields[2], componentDelim);
    string[] recipientParts = splitByDelimiter(unbFields[3], componentDelim);
    string[] dateTimeParts = splitByDelimiter(unbFields[4], componentDelim);

    EdifactUNB unb = {
        syntaxIdentifier: {
            syntaxId: syntaxParts.length() > 0 ? syntaxParts[0].trim() : "",
            syntaxVersion: syntaxParts.length() > 1 ? syntaxParts[1].trim() : ""
        },
        sender: {
            id: senderParts.length() > 0 ? senderParts[0].trim() : "",
            qualifier: senderParts.length() > 1 ? senderParts[1].trim() : ""
        },
        recipient: {
            id: recipientParts.length() > 0 ? recipientParts[0].trim() : "",
            qualifier: recipientParts.length() > 1 ? recipientParts[1].trim() : ""
        },
        dateAndTime: {
            date: dateTimeParts.length() > 0 ? dateTimeParts[0].trim() : "",
            time: dateTimeParts.length() > 1 ? dateTimeParts[1].trim() : ""
        },
        controlRef: unbFields.length() > 5 ? unbFields[5].trim() : ""
    };

    // Try to find UNH
    EdifactUNH? unh = ();
    string afterUNB = remaining.length() > unbEnd + 1 ? remaining.substring(unbEnd + 1) : "";
    string nextSeg = afterUNB.trim();
    if nextSeg.startsWith("UNH") {
        int unhEnd = nextSeg.indexOf(segmentTerminator) ?: nextSeg.length();
        string unhText = nextSeg.substring(0, unhEnd);
        string[] unhFields = splitByDelimiter(unhText, fieldDelim);
        if unhFields.length() >= 3 {
            string[] msgIdParts = splitByDelimiter(unhFields[2], componentDelim);
            unh = {
                messageRef: unhFields.length() > 1 ? unhFields[1].trim() : "",
                messageIdentifier: {
                    messageType: msgIdParts.length() > 0 ? msgIdParts[0].trim() : "",
                    version: msgIdParts.length() > 1 ? msgIdParts[1].trim() : "",
                    release: msgIdParts.length() > 2 ? msgIdParts[2].trim() : "",
                    controlAgency: msgIdParts.length() > 3 ? msgIdParts[3].trim() : ""
                }
            };
        }
    }

    return {unb, unh};
}

# Reads EDIFACT interchange headers from a file without requiring a schema.
#
# + filePath - Path to the EDI file
# + return - Parsed EdifactHeaders, or Error if the file cannot be read or UNB cannot be parsed
public isolated function edifactHeadersFromFile(string filePath) returns EdifactHeaders|Error {
    string|io:Error ediText = io:fileReadString(filePath);
    if ediText is io:Error {
        return error Error(string `Failed to read file '${filePath}': ${ediText.message()}`);
    }
    return edifactHeadersFromEdiString(ediText);
}

# Parses only the envelope header segments defined in the schema and stops.
# Reads interchange headers, group headers (if defined), and transaction headers.
#
# Requires `schema.envelope` to be non-nil. Returns an error if called
# with a schema that has no `envelope` (i.e. an older schema).
#
# + ediText - EDI text to read
# + schema - Schema containing an `envelope` definition
# + return - JSON representation of the parsed header segments, or Error
public isolated function headersFromEdiString(string ediText, EdiSchema schema) returns json|Error {
    EdiEnvelopeSchema? envelope = schema.envelope;
    if envelope is () {
        return error Error(
            string `Schema '${schema.name}' has no envelope defined. ` +
            "Regenerate the schema using the latest edi-tools to use this function."
        );
    }
    EdiContext context = {schema};
    context.ediText = check splitSegments(ediText, schema.delimiters.segment);

    // Parse interchange headers
    EdiSegmentGroup interchangeHeaders = check readSegmentGroup(envelope.interchange.header, context, false);

    // Parse group headers if group level is defined
    EdiSegmentGroup? groupHeaders = ();
    EdiEnvelopeLevel? group = envelope.group;
    if group is EdiEnvelopeLevel {
        groupHeaders = check readSegmentGroup(group.header, context, false);
    }

    // Parse transaction headers
    EdiSegmentGroup transactionHeaders = check readSegmentGroup(envelope.'transaction.header, context, false);

    // Combine all headers into a single JSON result
    map<json> result = {};
    map<json> ichMap = check interchangeHeaders.cloneWithType();
    foreach [string, json] [k, v] in ichMap.entries() {
        result[k] = v;
    }
    if groupHeaders is EdiSegmentGroup {
        map<json> grpMap = check groupHeaders.cloneWithType();
        foreach [string, json] [k, v] in grpMap.entries() {
            result[k] = v;
        }
    }
    map<json> txnMap = check transactionHeaders.cloneWithType();
    foreach [string, json] [k, v] in txnMap.entries() {
        result[k] = v;
    }
    return result;
}

# Parses the full envelope hierarchy and returns an EdiInterchange.
# Envelope (headers/trailers) is fail-fast; transaction body is fail-safe
# (malformed body is preserved as a raw string).
#
# Requires `schema.envelope` to be non-nil. Returns an error if called
# with a schema that has no `envelope`.
#
# + ediText - EDI text to read
# + schema - Schema containing an `envelope` definition
# + return - Parsed interchange or error
public isolated function interchangeFromEdiString(string ediText, EdiSchema schema) returns EdiInterchange|Error {
    EdiEnvelopeSchema? envelope = schema.envelope;
    if envelope is () {
        return error Error(
            string `Schema '${schema.name}' has no envelope defined. ` +
            "Regenerate the schema using the latest edi-tools to use this function."
        );
    }

    string[] allSegments = check splitSegments(ediText, schema.delimiters.segment);
    EdiContext context = {schema, ediText: allSegments};

    // Parse interchange header
    EdiSegmentGroup interchangeHeader = check readSegmentGroup(envelope.interchange.header, context, false);

    EdiEnvelopeLevel? group = envelope.group;
    EdiFunctionalGroup[]? groups = ();
    EdiTransaction[]? transactions = ();

    if group is EdiEnvelopeLevel {
        // With group level: parse groups, each containing transactions
        EdiFunctionalGroup[] groupList = [];
        string[] groupHeaderCodes = getSegmentCodes(group.header);
        while context.rawIndex < allSegments.length() && segmentStartsWithAny(allSegments, context.rawIndex, groupHeaderCodes, schema) {
            EdiSegmentGroup groupHeader = check readSegmentGroup(group.header, context, false);
            EdiTransaction[] txns = check parseTransactions(envelope.'transaction, schema, allSegments, context);
            EdiSegmentGroup groupTrailer = check readSegmentGroup(group.trailer, context, false);
            groupList.push({groupHeader, transactions: txns, groupTrailer});
        }
        groups = groupList;
    } else {
        // No group level: transactions directly under interchange
        transactions = check parseTransactions(envelope.'transaction, schema, allSegments, context);
    }

    // Parse interchange trailer
    EdiSegmentGroup interchangeTrailer = check readSegmentGroup(envelope.interchange.trailer, context, false);

    if groups is EdiFunctionalGroup[] {
        return {interchangeHeader, groups, interchangeTrailer};
    }
    return {interchangeHeader, transactions, interchangeTrailer};
}

// Parses transactions within the current context until the next segment is not
// a transaction header.
isolated function parseTransactions(EdiEnvelopeLevel txnLevel, EdiSchema schema,
        string[] allSegments, EdiContext context) returns EdiTransaction[]|Error {
    EdiTransaction[] txns = [];
    string[] txnHeaderCodes = getSegmentCodes(txnLevel.header);
    string[] txnTrailerCodes = getSegmentCodes(txnLevel.trailer);

    while context.rawIndex < allSegments.length() && segmentStartsWithAny(allSegments, context.rawIndex, txnHeaderCodes, schema) {
        // Parse transaction header
        EdiSegmentGroup txnHeader = check readSegmentGroup(txnLevel.header, context, false);

        // Collect body segments until trailer
        int bodyStart = context.rawIndex;
        while context.rawIndex < allSegments.length() &&
                !segmentStartsWithAny(allSegments, context.rawIndex, txnTrailerCodes, schema) {
            context.rawIndex += 1;
        }

        // Try to parse body; on failure, preserve as raw string (fail-safe)
        json|string body;
        if schema.segments.length() > 0 {
            string[] bodySegments = allSegments.slice(bodyStart, context.rawIndex);
            EdiContext bodyContext = {schema, ediText: bodySegments};
            EdiSegmentGroup|Error bodyResult = readSegmentGroup(schema.segments, bodyContext, false);
            if bodyResult is Error {
                // Fail-safe: join body segments as raw string
                body = joinSegments(bodySegments, schema.delimiters.segment);
            } else {
                body = bodyResult;
            }
        } else {
            // No body schema defined — preserve as raw string
            string[] bodySegments = allSegments.slice(bodyStart, context.rawIndex);
            body = joinSegments(bodySegments, schema.delimiters.segment);
        }

        // Parse transaction trailer
        EdiSegmentGroup txnTrailer = check readSegmentGroup(txnLevel.trailer, context, false);
        txns.push({transactionHeader: txnHeader, body, transactionTrailer: txnTrailer});
    }
    return txns;
}

// Returns the top-level segment codes declared in a list of EdiUnitSchemas.
isolated function getSegmentCodes(EdiUnitSchema[] schemas) returns string[] {
    string[] codes = [];
    foreach EdiUnitSchema s in schemas {
        if s is EdiSegSchema {
            codes.push(s.code);
        } else if s is EdiSegGroupSchema {
            foreach EdiUnitSchema child in s.segments {
                if child is EdiSegSchema {
                    codes.push(child.code);
                    break;
                }
            }
        } else if s is EdiUnitRef {
            codes.push(s.ref);
        }
    }
    return codes;
}

// Checks if the segment at the given index starts with any of the given codes.
isolated function segmentStartsWithAny(string[] allSegments, int index, string[] codes, EdiSchema schema) returns boolean {
    if index >= allSegments.length() {
        return false;
    }
    string segText = removeLineBreaks(allSegments[index]).trim();
    foreach string ignoreSegment in schema.ignoreSegments {
        if segText.startsWith(ignoreSegment) {
            return false;
        }
    }
    foreach string code in codes {
        if segText.startsWith(code) {
            return true;
        }
    }
    return false;
}

// Joins segments back into a single string using the segment delimiter.
isolated function joinSegments(string[] segments, string delimiter) returns string {
    string result = "";
    foreach int i in 0 ..< segments.length() {
        if i > 0 {
            result += delimiter;
        }
        result += segments[i];
    }
    return result;
}

// Splits a string by a single-character delimiter without using regex.
isolated function splitByDelimiter(string text, string delimiter) returns string[] {
    string[] parts = [];
    int start = 0;
    int i = 0;
    while i < text.length() {
        if text.substring(i, i + 1) == delimiter {
            parts.push(text.substring(start, i));
            start = i + 1;
        }
        i += 1;
    }
    parts.push(text.substring(start));
    return parts;
}
