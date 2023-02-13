+++
title = "Getting the CRTP Certification: 'Attacking and Defending Active Directory' Course Review"
date = "2020-10-13"
toc = true
draft = false
type = ["posts","post"]
tags = [
    "CRTP",
    "Active Directory",
    "Hacking",
]

[ author ]
  name = "Cas van Cooten"
+++

*Updated **February 13th, 2023**: The CRTP certification is now licensed by AlteredSecurity instead of PentesterAcademy, this blog post has been updated to reflect.*

## Introduction

As a red teamer -or as a hacker in general- you're guaranteed to run into Microsoft's Active Directory sooner or later. Almost every major organization uses Active Directory (which we will mostly refer to as 'AD') to manage authentication and authorization of servers and workstations in their environment. It is a complex product, and managing it securely becomes increasingly difficult at scale. 

It is exactly for this reason that AD is so interesting from an offensive perspective. Due to the scale of most AD environments, misconfigurations that allow for lateral movement or privilege escalation on a domain level are almost always present. If you can effectively identify and exploit these misconfigurations, you can compromise an entire organization without even launching an exploit at a single server. Sounds cool, right? 

Unfortunately, as mentioned, AD is a complex product and identifying and exploiting misconfigurations in AD environments is not always trivial. Furthermore, it can be daunting to "start with" AD exploitation because there's simply so much to learn. That's where the ['Attacking and Defending Active Directory Lab' course by AlteredSecurity](https://www.alteredsecurity.com/adlab) comes in!

This course will grant you the Certified Red Team Professional (CRTP) certification if you manage to best the exam, and it will set you up with a sound foundation for further AD exploitation adventures! In this blog, I will be reviewing this course based on my own experiences with it (on the date of publishing this blog I got confirmation that I passed the exam 🎉).

## The Course

The course describes itself as a "beginner friendly" course, supported by a lab environment "for security professionals to understand, analyze, and practice threats and attacks in a modern Active Directory Environment". The theoretical part of the course is comprised of 37 videos (totaling approximately 14 hours of video material), explaining the various concepts and as well as walking through the various learning goals. An overview of the video material is provided on the [course page](https://www.alteredsecurity.com/adlab).

> Keep in mind that this course is aimed at beginners, so if you're familiar with Windows exploitation and/or Active Directory you will know a lot of the covered contents. Still, the discussion of underlying concepts will help even experienced red teamers get a better grip on the logic behind AD exploitation.

The course theory, though not always living up to a high quality standard in terms of presentation and slide material, excels in terms of subject matter. The discussed concepts are relevant and actionable in real-life engagements. The outline of the course is as follows.

- Domain Enumeration
- Local Privilege Escalation
- Lateral Movement
- Domain Persistence
- Domain Privilege Escalation
- Cross-Forest Attacks
- Forest Persistence
- Detection and Defense

Since I have some experience with hacking through my work and OSCP (see my earlier blog posts 🙃), the section on privesc as well as some basic AD concepts were familiar to me. However, I was caught by surprise on how much new techniques there are to discover, especially in the domain persistence section (often overlooked!). 

You may notice that there is only one section on detection and defense. While interesting, this is _not_ the main selling point of the course. If you're a blue teamer looking to improve their AD defense skills, this course will help you understand the 'red' mindset, possible configuration flaws, and to some extent how to monitor and detect attacks on these flaws. However, the exam is fully focused on red so I would say just the course materials should suffice for most blue teamers (unless you're up for an offensive challenge!).

To help you judge whether or not this course is for you, here are some of the key techniques discussed in the course. If you know all of the below, then this course is probably not for you! *Note, this list is not exhaustive and there are much more concepts discussed during the course.*

- Domain enumeration, manual and using BloodHound (♥)
- Kerberoasting, AS-REP roasting
- ACL-based attacks and persistence mechanisms
- Golden- and silver ticket attacks
- Constrained- and unconstrained delegation attacks
- Domain trust abuse, inter- and intra-forest
- Basic MSSQL-based lateral movement techniques
- Basic Antivirus, AMSI, and AppLocker evasion
- Persistence attacks, such as DCShadow, Skeleton Key, DSRM admin abuse, etc.

## The Labs

Where this course shines, in my opinion, is the lab environment. Overall, the lab environment of this course is nothing advanced, but it's the most stable and accessible lab environment I've seen so far. AlteredSecurity provides VPN access as well as online RDP access over Guacamole. I'm usually not a big fan of online access, but in this instance it works really well and it makes the course that much more accessible. 

The environment itself contains approximately 10 machines, spread over two forests and various child forests. It is explicitly _not_ a challenge lab, rather AlteredSecurity describes it as a "practice lab". This checks out - if you just rush through the labs it will maybe take you a couple of hours to become Enterprise Admin. If you however use them as they are designed and take multiple approaches to practicing a variety of techniques, they will net you a lot more value.

> If you are looking for a challenge lab to test your skills without as much guidance, maybe the [HackTheBox Pro Labs](https://help.hackthebox.eu/forindividuals/what-are-prolabs) or the [CRTE course](https://www.alteredsecurity.com/redteamlab) are more for you!

During the course, mainly PowerShell-based tools are used for enumeration and exploitation of AD vulnerabilities (this makes sense, since the instructor is the author of [Nishang](https://github.com/samratashok/nishang)). However, it is expressed multiple times that you are _not_ bound to the tools discussed in the course - and I, too, would encourage you to use your lab time to practice a variety of tools, techniques, and even C2 frameworks. The lab is not internet-connected, but through the VPN endpoint the hosts can reach your machine (and as such, hosted files). 

Personally, I ran through the learning objectives using the recommended, PowerShell-based, tools. I ran through the labs a second time using Cobalt Strike and .NET-based tools, which confronted me with a whole range of new challenges and learnings. Due to the accessibility of the labs, it provides a great environment to test new tools and techniques as you discover them.

## The Exam

The CRTP certification exam is not one to underestimate. It consists of five target machines, spread over multiple domains. This is not counting your student machine, on which you start with a low-privileged foothold (similar to the labs). The goal is to get command execution (not necessarily privileged) on all of the machines. Similar to OSCP, you get 24 hours to complete the practical part of the exam. After that, you get another 48 hours to complete and submit your report.

I experienced the exam to be in line with the course material in terms of required knowledge. That does not mean, however, that you will be able to complete the exam with _just_ the tools and commands from the course! The exam will contain some interesting variants of covered techniques, and some steps that are quite well-hidden and require careful enumeration. That said, the course itself provides a good foundation for the exam, and if you ran through all the learning objectives and -more importantly- understand the covered concepts, you will be more than likely good to go.

In total, the exam took me 7 hours to complete. Machines #2 and #3 in my version of the exam took me the most time due to some tooling issues and very extensive required enumeration, respectively. Otherwise, the path to exploitation was pretty clear, and exploiting identified misconfigurations is fairly straightforward for the most part. As such, I think the 24 hours should be enough to compromise the labs if you spent enough time preparing. Additionally, I read online that it is not necessarily required to compromise all five machines, but I wouldn't bet on this as AlteredSecurity is not very transparent on the passing requirements!

The exam requires a report, for which I reflected [my reporting strategy for OSCP](https://cas.vancooten.com/posts/2020/05/generating-pretty-pwk-reports-with-pandoc-and-markdown-templates-inside/). I prepared the overall report template beforehand (based on my [PWK reporting templates](https://github.com/chvancooten/OSCP-MarkdownReportingTemplates)), and used a wireframe Markdown template to keep notes as I went. After completing the exam, I finalized my notes, merged them into the master document, converted it to Word format using Pandoc, and spend about 30 minutes styling my report (I'm a perfectionist, I know). Overall, the full exam cost me 10 hours, including reporting and some breaks. 

I can obviously not include my report as an example, but the Table of Contents looked as follows.

![PWK Lab Progression](/images/crtp-report.png) 

## CRTP Preparation Tips

So, you've decided to take the plunge and register for CRTP? Cool! Please find below some of my tips that will help you prepare for, and hopefully nail, the CRTP certification (and beyond). As always, don't hesitate to reach out [on Twitter](https://twitter.com/chvancooten) if you have some unanswered questions or concerns. Always happy to help!

- **Choose the right timing:** Even though this course is specifically for beginners, it may not be the most suitable course to start your hacking career with (depending on your desired career path). General exploitation and hacking handicraft are not covered as much as they are with e.g. OSCP, as the course focuses solely on AD exploitation (with a _very_ brief primer on local privilege escalation for Windows). However, if you are a beginning red teamer looking to get a better track record with AD, this course is likely a step in the right direction. Obviously, there's no right order in which to take courses, just think about your current skillset and desired development path, then decide if this course fits the bill.
- **Enrich the theory:** Even though the videos and course guide do a good job of walking you through the various subjects, I can always recommend doing your own research in addition to the provided videos. Reading e.g. blogs on tools and techniques that you use will greatly help improve your insight and help actualize your skills even more.
- **Get comfortable in the labs:** Depending on the amount of lab time you have, there's probably no rush. The CRTP course is doable in about one month, but that does not mean you should limit your lab time to 30 days. I would recommend getting more time, especially if you want to research techniques and play around in the labs on your own to try out your new hacking toys in a safe environment. 
- **Create a cheat sheet:** You will find yourself using a lot of similar commands during the course and exam. As such, it's useful to create a list of your favorite and most-used commands, so you can simply copy and paste without looking up the syntax every time. Furthermore, a structured cheat sheet will help you ensure that you don't overlook anything in your enumeration, something that is _very_ important for CRTP.
- **Prepare your report beforehand:** Even though CRTP gives you 48 hours to come up with a report, creating a report template will help you mentally prepare for the exam as well as structure your as-you-go notes in advance. Doing this will prevent you having to do a lot of writing and note adaptation after you finished your exam. 

**So... Where's that cheat sheet?**

As you may have guessed based on the above, I compiled a cheat sheet and command reference based on the theory discussed during CRTP. I enriched this with some commands I personally use a lot for AD enumeration and exploitation.

I will publish this cheat sheet on this blog, but since I'm set to do CRTE (the [Red Teaming Labs](https://www.alteredsecurity.com/redteamlab) offered by AlteredSecurity) soon, I will hold off publishing my cheat sheet until after this so that I can aggregate and finalize the listed commands and techniques. If you're hungry for cheat sheets in the meantime, [you can find my OSCP cheat sheet here](https://cas.vancooten.com/posts/2020/05/oscp-cheat-sheet-and-command-reference/). Watch this space for more soon!