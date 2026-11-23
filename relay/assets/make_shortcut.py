#!/usr/bin/env python3
"""Build the iPhone "Send to assistant" Shortcut (unsigned).

    python3 relay/assets/make_shortcut.py [RELAY_URL] > send-to-assistant.unsigned.shortcut
    shortcuts sign --mode anyone --input send-to-assistant.unsigned.shortcut \
        --output relay/assets/send-to-assistant.shortcut      # on a Mac

The Shortcut shows up in the share sheet for photos. It converts the photo
to JPEG (assistants can't read HEIC) and posts it to RELAY_URL/phone/share
with the phone key, which it asks for when it's added (the phone page
shows the key), then shows the relay's answer as a notification.
"""
import plistlib
import sys
import uuid

relay = (sys.argv[1] if len(sys.argv) > 1 else "https://opendrop-relay-aj.fly.dev").rstrip("/")

KEY, URL, JPEG, POST = (str(uuid.uuid4()).upper() for _ in range(4))
OBJ = "￼"  # where a variable sits in a text field


def output(uuid_, name):
    return {"Type": "ActionOutput", "OutputUUID": uuid_, "OutputName": name}


def text(s, **vars_at):
    """A text field; vars_at maps an index in `s` (an OBJ) to a variable."""
    return {
        "Value": {
            "string": s,
            "attachmentsByRange": {f"{{{i}, 1}}": v for i, v in vars_at.items()},
        },
        "WFSerializationType": "WFTextTokenString",
    }


def var(v):
    return {"Value": v, "WFSerializationType": "WFTextTokenAttachment"}


def action(ident, **params):
    return {"WFWorkflowActionIdentifier": ident, "WFWorkflowActionParameters": params}


actions = [
    # 0: the phone key (asked for on import)
    action("is.workflow.actions.gettext", UUID=KEY, WFTextActionText=""),
    # 1: the relay address (asked for on import, filled in)
    action("is.workflow.actions.gettext", UUID=URL, WFTextActionText=relay),
    # 2: the shared photo as JPEG
    action(
        "is.workflow.actions.image.convert",
        UUID=JPEG,
        WFInput=var({"Type": "ExtensionInput"}),
        WFImageFormat="JPEG",
        WFImageCompressionQuality=0.85,
        WFImagePreserveMetadata=False,
    ),
    # 3: post it to the inbox
    action(
        "is.workflow.actions.downloadurl",
        UUID=POST,
        WFURL=text(f"{OBJ}/phone/share", **{"0": output(URL, "Text")}),
        WFHTTPMethod="POST",
        WFHTTPBodyType="Form",
        ShowHeaders=True,
        WFHTTPHeaders={
            "Value": {
                "WFDictionaryFieldValueItems": [
                    {
                        "WFItemType": 0,
                        "WFKey": text("Authorization"),
                        "WFValue": text(f"Bearer {OBJ}", **{"7": output(KEY, "Text")}),
                    }
                ]
            },
            "WFSerializationType": "WFDictionaryFieldValue",
        },
        WFFormValues={
            "Value": {
                "WFDictionaryFieldValueItems": [
                    {
                        "WFItemType": 5,
                        "WFKey": text("file"),
                        "WFValue": var(output(JPEG, "Converted Image")),
                    }
                ]
            },
            "WFSerializationType": "WFDictionaryFieldValue",
        },
    ),
    # 4: say what happened
    action(
        "is.workflow.actions.notification",
        WFNotificationActionTitle="OpenDrop",
        WFNotificationActionBody=text(OBJ, **{"0": output(POST, "Contents of URL")}),
        WFNotificationActionSound=False,
    ),
]

shortcut = {
    "WFWorkflowClientVersion": "2302.0.4",
    "WFWorkflowMinimumClientVersion": 900,
    "WFWorkflowMinimumClientVersionString": "900",
    "WFWorkflowIcon": {
        "WFWorkflowIconStartColor": 1440408063,  # blue
        "WFWorkflowIconGlyphNumber": 59511,
    },
    "WFWorkflowTypes": ["ActionExtension"],
    "WFWorkflowInputContentItemClasses": ["WFImageContentItem"],
    "WFWorkflowHasShortcutInputVariables": True,
    "WFWorkflowOutputContentItemClasses": [],
    "WFWorkflowImportQuestions": [
        {
            "ActionIndex": 0,
            "Category": "Parameter",
            "ParameterKey": "WFTextActionText",
            "Text": "Paste the key from the OpenDrop phone page (Send to assistant).",
            "DefaultValue": "",
        },
        {
            "ActionIndex": 1,
            "Category": "Parameter",
            "ParameterKey": "WFTextActionText",
            "Text": "Your OpenDrop relay's address.",
            "DefaultValue": relay,
        },
    ],
    "WFWorkflowActions": actions,
}

sys.stdout.buffer.write(plistlib.dumps(shortcut, fmt=plistlib.FMT_BINARY))
