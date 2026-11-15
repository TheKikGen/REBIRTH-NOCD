#!/usr/bin/env python3
"""
=============================================================================
ReBirth RB-338 v2.0.1 - Help File to Markdown Manual Converter
=============================================================================
Parses the extracted WinHelp JSON structure and generates a comprehensive,
fully structured, clean Markdown user manual with images and cross-references.
=============================================================================
"""

import json
import os
import re

def format_markdown_body(text):
    if not text:
        return ""
    lines = [l.strip() for l in text.splitlines()]
    res = []
    for l in lines:
        if not l:
            if res and res[-1] != "":
                res.append("")
            continue
        # Check if list item (1., 2., etc.)
        m = re.match(r"^(\d+\.)\s*(.*)", l)
        if m:
            res.append(f"{m.group(1)} {m.group(2)}")
        elif l.startswith("-") or l.startswith("•") or l.startswith("*"):
            res.append(f"- {l.lstrip('-•* ')}")
        else:
            if res and res[-1] != "" and not re.match(r"^(\d+\.)", res[-1]) and not res[-1].startswith("- "):
                res[-1] += " " + l
            else:
                res.append(l)
    return "\n\n".join([r for r in res if r])

def get_topic_data(topic):
    spans = topic.get("text_spans", [])
    raw = "".join(s.get("text", "") for s in spans).strip()
    lines = [l.strip() for l in raw.splitlines() if l.strip()]
    
    explicit_title = topic.get("title")
    if explicit_title:
        title = explicit_title.strip()
    elif lines:
        title = lines[0]
    else:
        title = "Untitled"
        
    # Remove leading title from body if duplicated
    if lines and lines[0].lower() == title.lower():
        body = format_markdown_body("\n".join(lines[1:]))
    elif lines and len(lines[0]) < 60 and not lines[0].endswith(".") and len(lines) > 1:
        body = format_markdown_body("\n".join(lines[1:]))
    else:
        body = format_markdown_body(raw)
        
    cnames = topic.get("context_names", [])
    return title, body, cnames

def build_markdown_manual(json_path, output_md_path):
    print(f"[*] Reading {json_path}...")
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    parsed_topics = data.get("topic", {}).get("parsed_topics", [])
    print(f"[*] Total parsed topics: {len(parsed_topics)}")

    topics_dict = {}
    for i, t in enumerate(parsed_topics):
        title, body, cnames = get_topic_data(t)
        topics_dict[i] = {
            "index": i,
            "title": title,
            "body": body,
            "context_names": cnames,
        }

    md = []
    md.append("# Propellerhead ReBirth RB-338 v2.0.1: Complete Reference Manual")
    md.append("\n> **Source:** Extracted directly from `ReBirth.hlp` (Windows Help 4.0 system) & `ReBirth.cnt`.")
    md.append("> Converted to modern Markdown for seamless offline reading, search, and archival on Windows 10/11, macOS, and Linux.\n")

    md.append("![ReBirth RB-338 Rack Overview](docs/images/bm3.png)\n")

    md.append("## Table of Contents")
    md.append("- [1. Initial Setup & Audio Configuration](#1-initial-setup--audio-configuration)")
    md.append("  - [1.1 Selecting a Card Driver](#11-selecting-a-card-driver)")
    md.append("  - [1.2 DirectX Drivers: Emulated vs. Native](#12-directx-drivers-emulated-vs-native)")
    md.append("  - [1.3 Selecting an MME Driver](#13-selecting-an-mme-driver)")
    md.append("  - [1.4 Setting the Audio Card Buffer](#14-setting-the-audio-card-buffer)")
    md.append("- [2. Menu Commands Reference](#2-menu-commands-reference)")
    md.append("  - [2.1 File Menu](#21-file-menu)")
    md.append("  - [2.2 Edit Menu](#22-edit-menu)")
    md.append("  - [2.3 Mods Menu](#23-mods-menu)")
    md.append("  - [2.4 Options Menu](#24-options-menu)")
    md.append("  - [2.5 Windows Menu](#25-windows-menu)")
    md.append("  - [2.6 Help Menu](#26-help-menu)")
    md.append("- [3. Dialog Windows Reference](#3-dialog-windows-reference)")
    md.append("  - [3.1 Song Information Dialog](#31-song-information-dialog)")
    md.append("  - [3.2 Transpose Dialog](#32-transpose-dialog)")
    md.append("  - [3.3 Preferences Dialog](#33-preferences-dialog)")
    md.append("  - [3.4 Quick Setup (MIDI Remote Control Mapping)](#34-quick-setup-midi-remote-control-mapping)")
    md.append("  - [3.5 Select Mod Dialog](#35-select-mod-dialog)")
    md.append("- [4. Panel & Instrument Controls Reference](#4-panel--instrument-controls-reference)")
    md.append("  - [4.1 The Active Device Concept & Focus Bar](#41-the-active-device-concept--focus-bar)")
    md.append("  - [4.2 Transport Panel](#42-transport-panel)")
    md.append("  - [4.3 Synth Sections (TB-303 Units 1 & 2)](#43-synth-sections-tb-303-units-1--2)")
    md.append("  - [4.4 808 Rhythm Section (TR-808 Drum Machine)](#44-808-rhythm-section-tr-808-drum-machine)")
    md.append("  - [4.5 909 Rhythm Section (TR-909 Drum Machine)](#45-909-rhythm-section-tr-909-drum-machine)")
    md.append("  - [4.6 Pattern Section](#46-pattern-section)")
    md.append("  - [4.7 Mixer Sections](#47-mixer-sections)")
    md.append("  - [4.8 PCF (Pattern Controlled Filter) Section](#48-pcf-pattern-controlled-filter-section)")
    md.append("  - [4.9 Delay Section](#49-delay-section)")
    md.append("  - [4.10 Distortion (Dist) Section](#410-distortion-dist-section)")
    md.append("  - [4.11 Compressor (Comp) Section](#411-compressor-comp-section)")
    md.append("  - [4.12 Master Section](#412-master-section)")
    md.append("- [5. General Help & System Notes](#5-general-help--system-notes)\n")
    md.append("---\n")

    # SECTION 1
    md.append("## 1. Initial Setup & Audio Configuration\n")
    for i, subtitle in [(0, "1.1 Selecting a Card Driver"),
                        (1, "1.2 DirectX Drivers: Emulated vs. Native"),
                        (2, "1.3 Selecting an MME Driver"),
                        (3, "1.4 Setting the Audio Card Buffer")]:
        t = topics_dict[i]
        md.append(f"### {subtitle}")
        if t["context_names"]:
            md.append(f"> Context Identifier: `{t['context_names'][0]}`\n")
        md.append(f"{t['body']}\n")

    # SECTION 2
    md.append("## 2. Menu Commands Reference\n")
    
    menus = [
        ("2.1 File Menu", range(5, 15)),
        ("2.2 Edit Menu", range(15, 30)),
        ("2.3 Mods Menu", range(30, 33)),
        ("2.4 Options Menu", range(33, 38)),
        ("2.5 Windows Menu", range(38, 40)),
        ("2.6 Help Menu", range(40, 48)),
    ]
    for menu_title, indices in menus:
        md.append(f"### {menu_title}\n")
        for idx in indices:
            t = topics_dict[idx]
            md.append(f"#### {t['title']}")
            if t["context_names"]:
                md.append(f"> Command ID: `{t['context_names'][0]}`\n")
            md.append(f"{t['body']}\n")

    # SECTION 3
    md.append("## 3. Dialog Windows Reference\n")
    
    dialogs = [
        ("3.1 Song Information Dialog", 48, range(49, 56)),
        ("3.2 Transpose Dialog", 56, range(57, 60)),
        ("3.3 Preferences Dialog", 60, range(61, 75)),
        ("3.4 Quick Setup (MIDI Remote Control Mapping)", 75, range(76, 83)),
        ("3.5 Select Mod Dialog", 83, range(84, 89)),
    ]
    for diag_title, main_idx, item_indices in dialogs:
        md.append(f"### {diag_title}\n")
        main_t = topics_dict[main_idx]
        md.append(f"{main_t['body']}\n")
        md.append("| Control / Field | Description |")
        md.append("|---|---|")
        for item_idx in item_indices:
            it = topics_dict[item_idx]
            name = it["title"]
            desc = it["body"].replace("\n\n", "<br><br>").replace("|", "\\|")
            md.append(f"| **{name}** | {desc} |")
        md.append("\n")

    # SECTION 4
    md.append("## 4. Panel & Instrument Controls Reference\n")
    
    # 4.1 Active Device
    md.append("### 4.1 The Active Device Concept & Focus Bar\n")
    md.append(f"{topics_dict[182]['body']}\n")

    panels = [
        ("4.2 Transport Panel", "docs/images/bm4.png", 91, range(92, 105)),
        ("4.3 Synth Sections (TB-303 Units 1 & 2)", "docs/images/bm5.png", 105, range(106, 123)),
        ("4.4 808 Rhythm Section (TR-808 Drum Machine)", "docs/images/bm6.png", 123, range(124, 130)),
        ("4.5 909 Rhythm Section (TR-909 Drum Machine)", "docs/images/bm7.png", 130, range(131, 136)),
        ("4.6 Pattern Section", "docs/images/bm8.png", 136, range(137, 142)),
        ("4.7 Mixer Sections", "docs/images/bm9.png", 142, range(143, 151)),
        ("4.8 PCF (Pattern Controlled Filter) Section", "docs/images/bm10.png", 151, range(152, 160)),
        ("4.9 Delay Section", "docs/images/bm11.png", 160, range(161, 166)),
        ("4.10 Distortion (Dist) Section", "docs/images/bm12.png", 166, range(167, 171)),
        ("4.11 Compressor (Comp) Section", "docs/images/bm13.png", 171, range(172, 177)),
        ("4.12 Master Section", "docs/images/bm14.png", 177, range(178, 181)),
    ]
    for panel_title, img_path, main_idx, control_indices in panels:
        md.append(f"### {panel_title}\n")
        if img_path:
            md.append(f"![{panel_title}]({img_path})\n")
        main_t = topics_dict[main_idx]
        if main_t["body"]:
            md.append(f"{main_t['body']}\n")
        md.append("| Knob / Control / Switch | Operational Description | Context ID |")
        md.append("|---|---|:---:|")
        for c_idx in control_indices:
            ct = topics_dict[c_idx]
            c_name = ct["title"]
            c_desc = ct["body"].replace("\n\n", "<br><br>").replace("|", "\\|")
            cid = ct["context_names"][0] if ct["context_names"] else "-"
            md.append(f"| **{c_name}** | {c_desc} | `{cid}` |")
        md.append("\n")

    # SECTION 5
    md.append("## 5. General Help & System Notes\n")
    if 184 in topics_dict:
        md.append(f"### About This Help System\n{topics_dict[184]['body']}\n")

    out_text = "\n".join(md)
    with open(output_md_path, "w", encoding="utf-8") as f:
        f.write(out_text)

    print(f"[+] Successfully generated Markdown documentation at: {output_md_path}")
    print(f"[*] Document length: {len(out_text)} characters, {len(md)} markdown blocks.")

if __name__ == "__main__":
    build_markdown_manual(
        "ReBirth RB-338/ReBirth_help.json",
        "ReBirth RB-338/REBIRTH_HELP_MANUAL.md"
    )
