#!/usr/bin/env python3
"""Writes the inputs that confirm the three integrity candidates on the real build.

Each file is  [request identity JSON] NUL [stored identity JSON], the service
harness's input format. Candidates should FAIL the experimental took-effect check
(an AssertionError), controls should PASS it. Run from any directory; the files
are written next to this script. See README, "Findings".
"""
import json
import os

UIN = "2419762130"
HERE = os.path.dirname(os.path.abspath(__file__))


def lang(*pairs):
    return [{"language": pairs[i], "value": pairs[i + 1]} for i in range(0, len(pairs), 2)]


def stored(**attrs):
    record = {"UIN": UIN, "IDSchemaVersion": 0.1}
    record.update(attrs)
    record["verifiedAttributes"] = []
    return record


CASES = {
    # 1: a change to an EXISTING language is dropped when the request lists fewer
    #    languages than are stored...
    "candidate1-fewer-languages": (
        {"city": lang("ara", "a")},
        stored(city=lang("ara", "c", "eng", "a"))),
    # ...or when the request also adds a new language
    "candidate1b-change-and-add-language": (
        {"city": lang("ara", "Y", "fra", "Z")},
        stored(city=lang("ara", "X"))),
    # 2: a new language added to several attributes in one update lands only in
    #    the first (alphabetically)
    "candidate2-new-language-in-three-attributes": (
        {"city": lang("ara", "x", "fra", "p"),
         "region": lang("ara", "y", "fra", "q"),
         "province": lang("ara", "z", "fra", "r")},
        stored(city=lang("ara", "x"), region=lang("ara", "y"), province=lang("ara", "z"))),
    # 3: the string "null" is treated as JSON null and the update is dropped
    "candidate3-string-null": (
        {"postalCode": "null"},
        stored(postalCode="14022")),
    # controls: the same kinds of update in the shape that is expected to work
    "control1-same-languages-one-changed": (
        {"city": lang("ara", "b", "eng", "a")},
        stored(city=lang("ara", "c", "eng", "a"))),
    "control2-one-attribute-adds-language": (
        {"city": lang("ara", "x", "fra", "p")},
        stored(city=lang("ara", "x"))),
    "control3-plain-text-change": (
        {"postalCode": "56789"},
        stored(postalCode="14022")),
}


def dump(obj):
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


if __name__ == "__main__":
    for name, (request, record) in CASES.items():
        path = os.path.join(HERE, name + ".bin")
        with open(path, "wb") as f:
            f.write(dump(request) + b"\x00" + dump(record))
        print("%-46s request %s" % (name + ".bin", json.dumps(request)))
