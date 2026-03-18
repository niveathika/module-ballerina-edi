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

import ballerina/test;
import ballerina/io;

// ── x12HeadersFromEdiString ───────────────────────────────────────────────────

@test:Config {}
function testX12HeadersFromEdiStringValid() returns error? {
    string ediText = check io:fileReadString("tests/resources/x12-envelope/message.edi");
    X12Headers headers = check x12HeadersFromEdiString(ediText);
    test:assertEquals(headers.isa.senderQualifier, "ZZ");
    test:assertEquals(headers.isa.senderId, "SENDAPP");
    test:assertEquals(headers.isa.receiverQualifier, "ZZ");
    test:assertEquals(headers.isa.receiverId, "RECVAPP");
    test:assertEquals(headers.isa.date, "260101");
    test:assertEquals(headers.isa.controlNumber, "000000001");
    test:assertEquals(headers.isa.usageIndicator, "T");
}

@test:Config {}
function testX12HeadersFromEdiStringWithGS() returns error? {
    string ediText = check io:fileReadString("tests/resources/x12-envelope/message.edi");
    X12Headers headers = check x12HeadersFromEdiString(ediText);
    X12GS? gs = headers.gs;
    test:assertTrue(gs !is (), "GS should be present");
    if gs is X12GS {
        test:assertEquals(gs.functionalIdentifier, "HI");
        test:assertEquals(gs.senderId, "SENDAPP");
        test:assertEquals(gs.receiverId, "RECVAPP");
    }
}

@test:Config {}
function testX12HeadersFromEdiStringNoGS() returns error? {
    string isaOnly = "ISA*00*          *00*          *ZZ*SENDER         *ZZ*RECEIVER       *260101*1200*^*00501*000000001*0*T*:~ST*278*0001~";
    X12Headers headers = check x12HeadersFromEdiString(isaOnly);
    test:assertEquals(headers.isa.senderId, "SENDER");
    test:assertEquals(headers.gs, ());
}

@test:Config {}
function testX12HeadersFromEdiStringInvalidInput() {
    X12Headers|Error result = x12HeadersFromEdiString("UNB+UNOA:1+SENDER+RECEIVER+260101:1200+1'");
    test:assertTrue(result is Error, "Expected an error for non-X12 input");
}

@test:Config {}
function testX12HeadersFromEdiStringTooShort() {
    X12Headers|Error result = x12HeadersFromEdiString("ISA*00*SHORT");
    test:assertTrue(result is Error, "Expected an error for truncated ISA");
}

// ── x12HeadersFromFile ────────────────────────────────────────────────────────

@test:Config {}
function testX12HeadersFromFile() returns error? {
    X12Headers headers = check x12HeadersFromFile("tests/resources/x12-envelope/message.edi");
    test:assertEquals(headers.isa.senderId, "SENDAPP");
    test:assertEquals(headers.isa.controlNumber, "000000001");
}

@test:Config {}
function testX12HeadersFromFileNotFound() {
    X12Headers|Error result = x12HeadersFromFile("tests/resources/nonexistent.edi");
    test:assertTrue(result is Error, "Expected an error for missing file");
}

// ── edifactHeadersFromEdiString ──────────────────────────────────────────────

@test:Config {}
function testEdifactHeadersFromEdiStringWithUNA() returns error? {
    string ediText = check io:fileReadString("tests/resources/edifact-envelope/message.edi");
    EdifactHeaders headers = check edifactHeadersFromEdiString(ediText);
    test:assertEquals(headers.unb.sender.id, "SENDAPP");
    test:assertEquals(headers.unb.recipient.id, "RECVAPP");
    test:assertEquals(headers.unb.dateAndTime.date, "260101");
    test:assertEquals(headers.unb.controlRef, "000000001");
    EdifactUNH? unh = headers.unh;
    test:assertTrue(unh !is (), "UNH should be present");
    if unh is EdifactUNH {
        test:assertEquals(unh.messageRef, "1");
        test:assertEquals(unh.messageIdentifier.messageType, "ORDERS");
    }
}

@test:Config {}
function testEdifactHeadersFromEdiStringWithoutUNA() returns error? {
    string ediText = "UNB+UNOA:1+SENDER:ZZ+RECEIVER:ZZ+260101:1200+REF001'UNH+1+INVOIC:D:96A:UN'BGM+380+INV001+9'";
    EdifactHeaders headers = check edifactHeadersFromEdiString(ediText);
    test:assertEquals(headers.unb.sender.id, "SENDER");
    test:assertEquals(headers.unb.controlRef, "REF001");
}

@test:Config {}
function testEdifactHeadersFromEdiStringNoUNB() {
    EdifactHeaders|Error result = edifactHeadersFromEdiString("BGM+380+INV001+9'");
    test:assertTrue(result is Error, "Expected an error when UNB is missing");
}

// ── edifactHeadersFromFile ───────────────────────────────────────────────────

@test:Config {}
function testEdifactHeadersFromFile() returns error? {
    EdifactHeaders headers = check edifactHeadersFromFile("tests/resources/edifact-envelope/message.edi");
    test:assertEquals(headers.unb.sender.id, "SENDAPP");
    test:assertEquals(headers.unb.controlRef, "000000001");
}

@test:Config {}
function testEdifactHeadersFromFileNotFound() {
    EdifactHeaders|Error result = edifactHeadersFromFile("tests/resources/nonexistent.edi");
    test:assertTrue(result is Error, "Expected an error for missing file");
}

// ── headersFromEdiString ──────────────────────────────────────────────────────

@test:Config {}
function testHeadersFromEdiStringX12() returns error? {
    EdiSchema schema = check getTestSchema("x12-envelope");
    string ediText = check io:fileReadString("tests/resources/x12-envelope/message.edi");
    json headers = check headersFromEdiString(ediText, schema);
    map<json> headersMap = check headers.cloneWithType();
    test:assertTrue(headersMap.hasKey("InterchangeControlHeader"), "Headers should contain InterchangeControlHeader");
    test:assertTrue(headersMap.hasKey("FunctionalGroupHeader"), "Headers should contain FunctionalGroupHeader");
    test:assertTrue(headersMap.hasKey("TransactionSetHeader"), "Headers should contain TransactionSetHeader");
}

@test:Config {}
function testHeadersFromEdiStringEdifact() returns error? {
    EdiSchema schema = check getTestSchema("edifact-envelope");
    string ediText = check io:fileReadString("tests/resources/edifact-envelope/message.edi");
    json headers = check headersFromEdiString(ediText, schema);
    map<json> headersMap = check headers.cloneWithType();
    test:assertTrue(headersMap.hasKey("InterchangeHeader"), "Headers should contain InterchangeHeader");
    test:assertTrue(headersMap.hasKey("MessageHeader"), "Headers should contain MessageHeader");
}

@test:Config {}
function testHeadersFromEdiStringOldSchemaShouldError() returns error? {
    EdiSchema schema = check getTestSchema("x12-278");
    json|Error result = headersFromEdiString("ST*278*0001~SE*1*0001~", schema);
    test:assertTrue(result is Error, "Expected an error for old schema without envelope");
    if result is Error {
        test:assertTrue(result.message().includes("envelope"), "Error message should mention envelope");
    }
}

// ── interchangeFromEdiString ──────────────────────────────────────────────────

@test:Config {}
function testInterchangeFromEdiStringX12() returns error? {
    EdiSchema schema = check getTestSchema("x12-envelope");
    string ediText = check io:fileReadString("tests/resources/x12-envelope/message.edi");
    EdiInterchange interchange = check interchangeFromEdiString(ediText, schema);

    // Interchange header should be parsed
    map<json> ichHeader = check interchange.interchangeHeader.cloneWithType();
    test:assertTrue(ichHeader.hasKey("InterchangeControlHeader"), "Should have InterchangeControlHeader");

    // Groups should be set (X12 has group level)
    EdiFunctionalGroup[]? groups = interchange.groups;
    test:assertTrue(groups !is (), "Groups should be set for X12");
    test:assertTrue(interchange.transactions is (), "Transactions should not be set when groups exist");

    if groups is EdiFunctionalGroup[] {
        test:assertEquals(groups.length(), 1, "Should have 1 group");
        EdiFunctionalGroup grp = groups[0];

        // Group header
        map<json> grpHeader = check grp.groupHeader.cloneWithType();
        test:assertTrue(grpHeader.hasKey("FunctionalGroupHeader"), "Should have FunctionalGroupHeader");

        // Transactions
        test:assertEquals(grp.transactions.length(), 1, "Should have 1 transaction");
        EdiTransaction txn = grp.transactions[0];

        // Transaction header
        map<json> txnHeader = check txn.transactionHeader.cloneWithType();
        test:assertTrue(txnHeader.hasKey("TransactionSetHeader"), "Should have TransactionSetHeader");

        // Body should be parsed (not a string)
        test:assertTrue(txn.body is json, "Body should be parsed JSON");

        // Transaction trailer
        map<json> txnTrailer = check txn.transactionTrailer.cloneWithType();
        test:assertTrue(txnTrailer.hasKey("TransactionSetTrailer"), "Should have TransactionSetTrailer");

        // Group trailer
        map<json> grpTrailer = check grp.groupTrailer.cloneWithType();
        test:assertTrue(grpTrailer.hasKey("FunctionalGroupTrailer"), "Should have FunctionalGroupTrailer");
    }

    // Interchange trailer
    map<json> ichTrailer = check interchange.interchangeTrailer.cloneWithType();
    test:assertTrue(ichTrailer.hasKey("InterchangeControlTrailer"), "Should have InterchangeControlTrailer");
}

@test:Config {}
function testInterchangeFromEdiStringEdifact() returns error? {
    EdiSchema schema = check getTestSchema("edifact-envelope");
    string ediText = check io:fileReadString("tests/resources/edifact-envelope/message.edi");
    EdiInterchange interchange = check interchangeFromEdiString(ediText, schema);

    // Interchange header
    map<json> ichHeader = check interchange.interchangeHeader.cloneWithType();
    test:assertTrue(ichHeader.hasKey("InterchangeHeader"), "Should have InterchangeHeader");

    // Transactions should be set directly (EDIFACT without groups)
    EdiTransaction[]? transactions = interchange.transactions;
    test:assertTrue(transactions !is (), "Transactions should be set for EDIFACT without groups");
    test:assertTrue(interchange.groups is (), "Groups should not be set when no group level");

    if transactions is EdiTransaction[] {
        test:assertEquals(transactions.length(), 1, "Should have 1 transaction");
        EdiTransaction txn = transactions[0];

        // Transaction header
        map<json> txnHeader = check txn.transactionHeader.cloneWithType();
        test:assertTrue(txnHeader.hasKey("MessageHeader"), "Should have MessageHeader");

        // Body should be parsed
        test:assertTrue(txn.body is json, "Body should be parsed JSON");

        // Transaction trailer
        map<json> txnTrailer = check txn.transactionTrailer.cloneWithType();
        test:assertTrue(txnTrailer.hasKey("MessageTrailer"), "Should have MessageTrailer");
    }

    // Interchange trailer
    map<json> ichTrailer = check interchange.interchangeTrailer.cloneWithType();
    test:assertTrue(ichTrailer.hasKey("InterchangeTrailer"), "Should have InterchangeTrailer");
}

@test:Config {}
function testInterchangeFromEdiStringOldSchemaShouldError() returns error? {
    EdiSchema schema = check getTestSchema("x12-278");
    EdiInterchange|Error result = interchangeFromEdiString("ST*278*0001~SE*1*0001~", schema);
    test:assertTrue(result is Error, "Expected an error for old schema without envelope");
}

// ── fromEdiString with envelope ───────────────────────────────────────────────

@test:Config {}
function testFromEdiStringWithEnvelopeX12() returns error? {
    EdiSchema schema = check getTestSchema("x12-envelope");
    string ediText = check io:fileReadString("tests/resources/x12-envelope/message.edi");
    json body = check fromEdiString(ediText, schema);
    map<json> bodyMap = check body.cloneWithType();
    // fromEdiString should skip envelope and return only the body (BHT segment)
    test:assertTrue(bodyMap.hasKey("BeginningOfHierarchicalTransaction"), "Body should contain BHT segment");
}

@test:Config {}
function testFromEdiStringWithEnvelopeEdifact() returns error? {
    EdiSchema schema = check getTestSchema("edifact-envelope");
    string ediText = check io:fileReadString("tests/resources/edifact-envelope/message.edi");
    json body = check fromEdiString(ediText, schema);
    map<json> bodyMap = check body.cloneWithType();
    // fromEdiString should skip envelope and return only the body (BGM segment)
    test:assertTrue(bodyMap.hasKey("BeginningOfMessage"), "Body should contain BGM segment");
}
