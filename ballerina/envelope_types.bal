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

// ── X12 Envelope Types ────────────────────────────────────────────────────────

# Represents the X12 ISA (Interchange Control Header) segment.
#
# + authInfoQualifier - Authorization information qualifier (ISA01)
# + authInfo - Authorization information (ISA02)
# + securityQualifier - Security information qualifier (ISA03)
# + securityInfo - Security information (ISA04)
# + senderQualifier - Interchange sender ID qualifier (ISA05)
# + senderId - Interchange sender ID (ISA06)
# + receiverQualifier - Interchange receiver ID qualifier (ISA07)
# + receiverId - Interchange receiver ID (ISA08)
# + date - Interchange date (ISA09)
# + time - Interchange time (ISA10)
# + version - Interchange control version number (ISA12)
# + controlNumber - Interchange control number (ISA13)
# + usageIndicator - Usage indicator: T=Test, P=Production, I=Information (ISA15)
public type X12ISA record {|
    string authInfoQualifier;
    string authInfo;
    string securityQualifier;
    string securityInfo;
    string senderQualifier;
    string senderId;
    string receiverQualifier;
    string receiverId;
    string date;
    string time;
    string version;
    string controlNumber;
    string usageIndicator;
|};

# Represents the X12 GS (Functional Group Header) segment.
#
# + functionalIdentifier - Functional identifier code (GS01)
# + senderId - Application sender's code (GS02)
# + receiverId - Application receiver's code (GS03)
# + date - Date (GS04)
# + time - Time (GS05)
# + controlNumber - Group control number (GS06)
# + version - Responsible agency code + version/release/industry identifier code (GS07+GS08)
public type X12GS record {|
    string functionalIdentifier;
    string senderId;
    string receiverId;
    string date;
    string time;
    string controlNumber;
    string version;
|};

# Represents parsed X12 interchange and functional-group envelope headers.
#
# + isa - Interchange Control Header (ISA segment)
# + gs - Functional Group Header (GS segment), present when available
public type X12Headers record {|
    X12ISA isa;
    X12GS gs?;
|};

// ── EDIFACT Envelope Types ────────────────────────────────────────────────────

# Represents the EDIFACT UNB (Interchange Header) segment.
#
# + syntaxIdentifier - Syntax identifier (UNB S001)
# + sender - Interchange sender (UNB S002)
# + recipient - Interchange recipient (UNB S003)
# + dateAndTime - Date/time of preparation (UNB S004)
# + controlRef - Interchange control reference (UNB 0020)
public type EdifactUNB record {|
    record {|
        string syntaxId;
        string syntaxVersion;
    |} syntaxIdentifier;
    record {|
        string id;
        string qualifier;
    |} sender;
    record {|
        string id;
        string qualifier;
    |} recipient;
    record {|
        string date;
        string time;
    |} dateAndTime;
    string controlRef;
|};

# Represents the EDIFACT UNH (Message Header) segment.
#
# + messageRef - Message reference number (UNH 0062)
# + messageIdentifier - Message identifier (UNH S009)
public type EdifactUNH record {|
    string messageRef;
    record {|
        string messageType;
        string version;
        string release;
        string controlAgency;
    |} messageIdentifier;
|};

# Represents parsed EDIFACT interchange and message envelope headers.
#
# + unb - Interchange Header (UNB segment)
# + unh - Message Header (UNH segment), present when available
public type EdifactHeaders record {|
    EdifactUNB unb;
    EdifactUNH unh?;
|};

// ── Hierarchical Interchange Result Types ─────────────────────────────────────

# A parsed EDI interchange containing the full envelope hierarchy.
# Exactly one of `groups` or `transactions` is set, depending on whether the
# schema defines a group level (e.g., GS/GE for X12).
#
# + interchangeHeader - Parsed interchange header segment(s)
# + groups - Functional groups (set when envelope.group exists in the schema)
# + transactions - Transactions directly under the interchange (set when envelope.group is absent)
# + interchangeTrailer - Parsed interchange trailer segment(s)
public type EdiInterchange record {|
    json interchangeHeader;
    EdiFunctionalGroup[] groups?;
    EdiTransaction[] transactions?;
    json interchangeTrailer;
|};

# A functional group within an interchange (e.g., GS...GE for X12).
#
# + groupHeader - Parsed group header segment(s)
# + transactions - Transactions within this group
# + groupTrailer - Parsed group trailer segment(s)
public type EdiFunctionalGroup record {|
    json groupHeader;
    EdiTransaction[] transactions;
    json groupTrailer;
|};

# A single transaction/message within the envelope.
# The body is parsed into a record on success, or preserved as a raw string on failure (fail-safe).
#
# + transactionHeader - Parsed transaction header segment(s)
# + body - Parsed transaction body or raw string if parsing failed
# + transactionTrailer - Parsed transaction trailer segment(s)
public type EdiTransaction record {|
    json transactionHeader;
    json|string body;
    json transactionTrailer;
|};
