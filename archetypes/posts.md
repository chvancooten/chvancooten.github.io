+++
title = "{{ replace .File.ContentBaseName "-" " " | title }}"
date = "{{ .Date | time.Format "2006-01-02" }}"
toc = true
draft = true
type = ["posts","post"]
# series = ["CheatSheets"]
tags = [
    "Hacking",
]

[ author ]
  name = "Cas van Cooten"
+++

## Introduction

Write the post here. Images go in `static/images/` and are linked as `![Alt text](/images/file.png)`.
