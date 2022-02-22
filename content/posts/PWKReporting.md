+++
title = "Generating pretty PWK reports with Pandoc and Markdown (templates inside!)"
date = "2020-05-07"
toc = true
type = ["posts","post"]
series = ["OSCP"]
tags = [
    "PWK",
    "OSCP",
    "Documentation",
    "Markdown",
    "Pandoc"
]

[ author ]
  name = "Cas van Cooten"
+++

For some people, the reporting bit of the PWK course may be their pride and joy leading up to their OSCP certification. For others, it's just a necessity that they want to get out of the way. Either way, handing in a report describing your findings is a requirement posed by Offensive Security - so you're gonna have to do it if you want to obtain that elusive OSCP certification! 

Luckily, reporting doesn't have to be a pain all the time. To the contrary, having a good process for documenting your findings in a structured way can be a big help for yourself as well, and it makes generating the final report that much easier! In this post, I will be sharing some of my personal tips and tricks for documentation and generating quality reports. 

To help you get started, I also published my personal Markdown templates (for individual machines, the lab report, and the exam report), as well as my Pandoc style [on Github](https://github.com/chvancooten/OSCP-MarkdownReportingTemplates). Feel free to create a pull request if you have any additions or improvements!

## Start from the top

Documenting your findings should not be something you wait with until you actually have to deliver your report. If you know what it is you need to document right from the start, you avoid having to re-exploit boxes just to run that one command or get that screenshot. As such, it helps to invest some time at the start of your PWK journey to understand what it is exactly that Offsec wants to see in your final report - especially if you aim to also deliver your lab report for bonus points. The [OSCP Exam Guide](https://support.offensive-security.com/oscp-exam-guide/) is a good place to start for that.

Once you understand what you need to document, I found that it helps greatly to maintain a template for your findings for every machine in the labs (mine is [here](https://github.com/chvancooten/OSCP-MarkdownReportingTemplates/blob/master/Machine%20template.md)). A template will help by providing structure in your notes, and it will also constantly remind you of the data you should collect on compromised systems.

> Having your template in an easy-to-use format (such as Markdown) helps in keeping reporting simple when you are executing your tests, while preserving the (logical) structure of your content. You can worry about layout and visuals later!

What also helped me for reporting specifically was to write my machine notes in a way that they could simply be copy-pasted into a final report. This way, I could simply just compile my machine notes and leave out the irrelevant bits to compile my report - saving me the headache of having to write out my exploitation path for 10+ machines post-hoc.

## Compiling the report

Once you made it to the end of your lab time and/or you completed the OSCP certification exam (👏), the time has come to compile your notes into a fully fledged report. Offensive Security offers their own [example report](https://www.offensive-security.com/pwk-online/PWK-Example-Report-v1.pdf), and they even have a bunch of [templates](https://support.offensive-security.com/pwk-reporting/). However, they do not restrict you to using these templates, so you are free to make of the report what you wish.

Since I did everything so far in Markdown, I decided to stick with that until the end. As such, I created my own [Lab Report template](https://github.com/chvancooten/OSCP-MarkdownReportingTemplates/blob/master/Lab%20Report%20template.md) and [Exam Report template](https://github.com/chvancooten/OSCP-MarkdownReportingTemplates/blob/master/Exam%20Report%20template.md) in Markdown, based on the examples provided by Offensive Security. Since the structure and contents provided in the official examples were... less than ideal, I also made some changes on that front. Of course you can change the preamble of your report as you wish, as long as you check the right boxes for PWK.

Once you have the foundation for your report, all that is left from a content perspective is to integrate it with your machine notes. This could be as simple as copy-pasting your machine write-ups in a logical order, or it may require some revisions to your contents. Either is fine!

> Since I had the notes of all 67 compromised lab machines in a report-ready format, I decided to be that one smartass that OffSec (probably) hates and include them all in my lab report 🤓. It turned out to be 485 pages, *heh*.

## Making it pretty

Great, so at this point you have a big blob of text with some headings and references to screenshots here and there. How to actually generate a report from that? Good question!

This is where [Pandoc](https://pandoc.org/) comes in. Pandoc is a free tool that allows for conversion between most text-based document formats - including Markdown, Word (docx), and PDF. There have been some efforts (e.g. [here](https://github.com/noraj/OSCP-Exam-Report-Template-Markdown)) to completely automate the conversion from Markdown to a readable PDF report, but I personally wanted to build in an in-between stage (i.e. Word) which allowed me to tweak the document exactly as desired.

To get Pandoc to generate a proper Word document, you need a document defining the base styles. If you will only generate one document it doesn't matter all that much since you could tweak the final document, but for PWK purposes it helps to define a solid base style (I shared mine [here](https://github.com/chvancooten/OSCP-MarkdownReportingTemplates/blob/master/custom-reference.docx)). In Pandoc you can also define a style for syntax highlighting, which is just perfect.

Of course, the benefit of generating a Word file in between your Markdown and the final PDF is flexibility. I used this flexibility to for example add a sleek-looking title page, generate a (proper) table of contents, add page numbers, and more. I'm about 95% sure you can also do these things with Pandoc, but I personally like the flexibility of having full control over a document before I select "export to PDF" and send it off.

> Specifics on my approach on report generation (like Pandoc commands) are available in the [repo readme](https://github.com/chvancooten/OSCP-MarkdownReportingTemplates).

## The final result

If you have been reading this up until this point (*yay*) you are probably wondering what this process will get you. Well, I got you! I've made an example report available [here](https://github.com/chvancooten/OSCP-MarkdownReportingTemplates/blob/master/Examples/Example%20Report.pdf) which is pretty much a carbon copy of my PWK lab report. Obviously, I cannot share any specific on the PWK labs or exam, so I replaced the actual contents with some VulnHub writeups to give you a better idea. Don't read the details if you want to avoid spoilers for Brainpan, Kioptrix2014, Zico, or LazyAdmin!

If you used any of these templates or techniques for your own reports I'm super curious to hear how you like it. Shoot me a message over on [Twitter](https://twitter.com/chvancooten) to let me know what you think!