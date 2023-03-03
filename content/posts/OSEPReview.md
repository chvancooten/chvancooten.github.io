+++
title = "Getting the OSEP Certification: 'Evasion Techniques and Breaching Defenses' (PEN-300) Course Review"
date = "2021-03-27"
toc = true
draft = false
type = ["posts","post"]
tags = [
    "OSEP",
    "PEN-300",
    "Hacking",
]

[ author ]
  name = "Cas van Cooten"
+++

*Updated **February 13th, 2023**: Some referenced courses are now licensed by AlteredSecurity instead of PentesterAcademy, this post has been udpated to reflect.*

## Introduction

When Offensive Security announced the new [PEN-300 course](https://www.offensive-security.com/pen300-osep/#course), also called "Evasion Techniques and Breaching Defenses", [the syllabus](https://www.offensive-security.com/documentation/PEN300-Syllabus.pdf) immediately intrigued me. The course promises to provide an advanced course, aimed at "OSCP-level penetration testers who want to develop their skills against hardened systems", and discusses more advanced penetration testing topics such as antivirus evasion, process injection and migration, bypassing application whitelisting and network filters, Windows/Linux post-exploitation and lateral movement (hello Active Directory!).

The course materials state that PEN-300 is a course focused at advanced penetration testing and explicitly *not* red teaming. However, I do believe that the discussed materials will provide a great foundation for pentesters and red teamers alike. Though more advanced topics such as EDR evasion are not discussed, the materials do focus on evading most common detection measures and operate in highly restrictive environments.

When I saw the first positive reviews of the PEN-300 course rolling in, it didn't take me long to enroll in the course. I ordered the 90 days package, since I took the course next to my full-time day job. Unless you can dedicate a lot of time I would probably advise most to do the same, even though it is possible to complete the full course materials and labs in way less time (I completed both in about six weeks). Do note that I completed the course during a Covid-lockdown, which gave me a bit more free time and flexibility in the evenings and weekends. 🙂

{{< tweet user="chvancooten" id="1374993077639733250" >}}

*As always - if you have any questions about the course that are unanswered in this post, please do [hit me up on Twitter](https://twitter.com/chvancooten). I'll gladly discuss any questions you may have (except specific questions on the exam, duh) and will add them to this post if relevant.*

## The Theory & Exercises

In my opinion, the course materials and the accompanying exercises are where the course really shines. Though the course doesn't discuss any ground-breaking new concepts or super-advanced techniques that you have never seen before, it does a great job at making you really understand the concepts required to be a better pentester and security researcher. Each chapter is paired with a dedicated lab environment, containing multiple machines (usually a Windows development machine and several target machines, containing specific software related to the chapter at hand). This makes it very easy to practice the theory discussed in the chapter in your own, dedicated, environment.

As with OSCP, the course offers the theory in both a 700-page PDF and approximately 19 hours of video. I found that I prefer going through the PDF at my own pace, interchanging that with the exercises. As such, I completely skipped over the videos. This is 100% personal preference though, as both media discuss the same materials.

The first part of the course goes over exploit development and AV evasion techniques, and has a strong focus on C# and PowerShell. Though I have relatively little experience programming in C#, the course really discusses the basic concepts well and also gives you the tools to go 'above and beyond' in building your own exploits. It's very easy to follow along, and you will be writing relatively complex exploits (e.g. an AV-safe process hollowing shellcode runner) in no-time! I would highly recommend also completing the "extra mile" exercises in this chapter, as these are the ones that really challenge you to one-up on the course materials and build some exploits based on research of your own.

For reference, I have published the code snippets I created as part of the OSEP code below. With the exception of the Python shellcode generator and some extra functionality I added here and there, you are guided through building all of these during the course. I would like to note explicitly that the purpose of me publishing this code is **not** for anyone to copy-paste it - I merely want to provide a reference of what you will be capable of doing after following the course in advance!

[![chvancooten/OSEP-Code-Snippets - GitHub](https://gh-card.dev/repos/chvancooten/OSEP-Code-Snippets.svg?fullname=)](https://github.com/chvancooten/OSEP-Code-Snippets)

Another part I particularly enjoyed were the chapters "Advanced Antivirus Evasion" and "Application Whitelisting". Both of these chapters discuss relatively simple concepts (AMSI bypasses and AppLocker bypasses, respectively), but dedicate a sizeable chunk to going through the process of finding and building your own bypasses by means of security research. For AMSI bypasses, this includes API hooking to identify the functions used, manually patching said functions to disrupt the expected result, and subsequently building an automated exploit. For the AppLocker bypass, this includes reverse-engineering a Microsoft-signed binary from start to finish to find a function that compiles and executes provided source code to execute arbitrary code in restricted environments. By going through these processes in detail, OffSec really aims to give you the tools and mindset to become a better security researcher in the long run. And that shows!

Two chapters that felt a bit out of place in the course were the chapters "Bypassing Network Filters" and "Kiosk Breakouts". The former discusses some interesting concepts (such as domain fronting), but it feels rushed, the exercises don't really teach you anything, and the lessons learnt don't really come back in the other chapters or the challenge labs. The kiosk breakout chapter is good fun and contains some nice exercises, but it discusses a *really* specific use case that you won't likely ever see in practice.

In the second part of the course there are two chapters discussing Linux post-exploitation and lateral movement. These chapters cover some interesting concepts such as AV evasion on Linux (easiest *ever*), some basic C development, and CI/CD or Ansible exploitation. However, they are way overshadowed by the focus on Windows / Active Directory in later chapters. These chapters contain a *lot* of relevant materials regarding domain/forest exploitation and lateral movement (including MSSQL exploitation). Though I already completed the CRTP and CRTE courses by AlteredSecurity which discuss largely the same concepts, I found that OffSec again does a good job of explaining in-depth the details you need to know. This helped me better understand some foundational concepts, such as the exact difference between the three types of delegation that exist in Microsoft's implementation of Kerberos. Though the exercises in these chapters take less effort than the ones in the first part of the course, I would definitely recommend giving them enough attention since these topics will be well-represented in the challenge labs (and likely the exam).

Since I already had a cheat sheet on Windows and Active Directory exploitation from CRTP/CRTE, I decided to enrich this with the tradecraft and nuances discussed in OSEP. As such, it may be a good help when you get stuck exploiting AD in OSEP now as well! If you haven't seen it, you can find that cheat sheet here: 
[Windows & Active Directory Exploitation Cheat Sheet and Command Reference](https://casvancooten.com/posts/2020/11/windows-active-directory-exploitation-cheat-sheet-and-command-reference/).

## The Challenge Labs

There are six challenge labs accompanying the course, each consisting of multiple target machines (up to 10 per lab!) and your trusty Windows development box. Some labs have a specific "theme" related to the various chapters in the theory, others are more generic and force you to combine all the pieces of what you have learnt. One big advantage compared to the OSCP labs is that all of these challenge lab environments are dedicated for you and as such can not be messed up by other people following the course.

The quality of the labs is really high, and some force you to combine some complex topics to progress. This makes the labs excellent practice for the exam. I would **strongly** recommend you to save all the additional exploits developed for the challenge labs, as those will definitely come in useful at a later point. 😏

That being said, I think the course could do with more challenge labs. I was able to complete all the labs in under two weeks, which is just too little if you compare it to the amount of course materials discussed. Another downside is that the labs are fairly single-use and do not offer many "alternate paths". You can go through them again for perfecting your techniques but you can never re-create the initial experience of figuring out what the hell you have to do to achieve your goals, unfortunately. 

## The Exam

For obvious reasons, I cannot go into too much details regarding the exam (and I will not answer questions about it in DMs, either). However, I do want to briefly discuss the overall experience of the exam as I thoroughly enjoyed it. The exam setup is quite different from other certification exams, and focuses on attaining a (realistic) exam objective rather than "just getting DA". The objective is represented by a file called `secret.txt`, and if you attain this objective you instantly satisfy the requirements for the practical side of the exam. You can also satisfy these requirements without getting to the objective, in this case you need to gather 100 points by submitting the OffSec-typical `local.txt` and `proof.txt` proof flags instead.

What I also like about the exam is that there are multiple distinct routes towards the objective. Each path has their own entry point and exploitation path all the way up to the objective. I was able to complete the first path and gain access to `secret.txt` in approximately 8 hours - including some 2 hours of delay because of a dumb (*really* dumb) oversight in my enumeration. Me being the completionist that I am, I wasn't satisfied with that result and wanted to complete all the exploitation paths. Unfortunately, due to reasons I won't disclose here, I was not able to do that and ended up giving up on 100% completion after several additional hours of failed exploitation efforts. 

Of course, to get the OSEP certification you also have to submit an exam report within 24 hours of your exam end time. The requirements for the report are well-documented by OffSec in their [OSEP exam guide](https://help.offensive-security.com/hc/en-us/articles/360050293792-OSEP-Exam-Guide). The report should contain reproducible steps, describing your exam exploitation shenanigans and proof files. After wrapping up the exam, I was able to generate my 70-page report in under two hours since I already documented my exploitation path really well as I went. I used Markdown templates similar to the ones I used for OSCP, and then compiled them into one master document and used Pandoc to generate a pretty report complete with syntax highlighting. If you are a fan of Markdown like I am, I would highly recommend this approach to reduce reporting effort and stress.

[![chvancooten/OSCP-MarkdownReportingTemplates - GitHub](https://gh-card.dev/repos/chvancooten/OSCP-MarkdownReportingTemplates.svg?fullname=)](https://github.com/chvancooten/OSCP-MarkdownReportingTemplates)

## Conclusion

I really enjoyed the PEN-300 "Evasion Techniques and Breaching Defenses" course by Offensive Security. It offers great coverage of a variety of interesting topics, and succeeds in guiding you through most of them really well. It would have been nice if OffSec streamlined some of the less relevant chapters and added some content on more relevant topics such as EDR evasion as well, but I can see why they passed on that. The challenge lab environments are great, but quite a bit too short for the price point that the course comes at. I would have liked to spend another couple weeks just exploiting target environments as with OSCP, but instead finished all the labs in 2 weeks which was a bit disappointing. Luckily, the exam made up for that by providing a realistic, objective-focused, and challenging experience. Overall, I would definitely recommend the course for anyone looking to sharpen their advanced pen-testing tradecraft.