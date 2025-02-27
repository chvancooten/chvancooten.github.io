  +++
title = "Operate Like You Mean It: 'Red Team Ops' (CRTO) Course Review"
date = "2021-07-10"
toc = true
draft = false
type = ["posts","post"]
tags = [
    "CRTO",
    "Red Team Ops",
    "Hacking",
]

[ author ]
  name = "Cas van Cooten"
+++

## Introduction

If you hang around the infosec "twittersphere" or in other security communities, odds are you have already seen someone share their experiences on the ['Red Team Ops' course by ZeroPointSecurity](https://www.zeropointsecurity.co.uk/red-team-ops). I had heard a *lot* about this course prior to enrolling in it myself - almost exclusively consisting of positive reviews. The author of the course, [RastaMouse](https://twitter.com/_RastaMouse), is quite a well-known figure in the infosec community. You may know him for his open-source tool contributions, such as [Watson](https://github.com/rasta-mouse/Watson) or [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck), or if you are a HackTheBox-enthusiast you may know him for the RastaLabs pro lab. 

Needless to say, I was quite intrigued about this red teaming course provided by his company ZeroPointSecurity. I enrolled in it not too long after passing the [OSEP certification](https://casvancooten.com/posts/2021/03/getting-the-osep-certification-evasion-techniques-and-breaching-defenses-pen-300-course-review/), excited to further build my knowledge and tradecraft as a red team operator!

The Red Team Ops course is hosted on the 'Canvas' Learning Management System. It consists of roughly two parts: the course itself, which contains various modules with theory and lab exercises, and the exam. Both need to be completed with a satisfactory result for the student to attain the "Certified Red Team Operator" (CRTO) certification. Progress is managed through "Badgr Pathways" within the Canvas platform.

![CRTO Pathway](/images/crto-pathway.png) 

## The Course

As mentioned, the course-side of the certification consists of a variety of modules, which contain the theoretical material of the course and lab exercises to test your understanding of the discussed subject matter. The figure above shows the 9 "main" modules, but these are only the modules that are graded through a lab exercise. At the time of writing, I counted 27 modules, each covering multiple subjects in varying levels of depth. The nice part about the course is that you get lifetime access to the materials, which are periodically updated by RastaMouse. As an example, the last update at the time of writing was mid-January, when a module on Kerberos Credential Cache was added to the course.

Let's start with "the good" of the course materials. RTO felt like a very welcome break from other courses, in the sense that the materials are very informative, concrete, and focused on day-to-day tradecraft. All techniques are demonstrated with a C2 framework (either Covenant or Cobalt Strike if you have a license), giving you the means to immediately start applying these techniques in practice. 

The modules cover a very broad range of interesting topics, such as the "standard" killchain (reconnaissance, initial access, lateral movement, etc.), [Active Directory exploitation](https://casvancooten.com/posts/2020/11/windows-active-directory-exploitation-cheat-sheet-and-command-reference/) (ranging from basic to advanced techniques), credentials and password cracking, AppLocker, AV evasion, advanced proxying techniques, and much more. I think the power of the course lies in the diversity of course material, which really set you up with a solid foundation of proven tradecraft as well as a solid toolset, no matter your experience level before coming into the RTO course. On top of that, RastaMouse really knows what he is talking about which does show in the materials. 

As with any course, there are also improvement points. My main issue with the course comes down to the same point that I listed as a 'pro' above - the course is quite focused on practical operations and tradecraft, so a lot of modules lack a clear background or explanation on the "why" of things. This means that the course will teach you quite some cool tricks, but it won't always equip you with the knowledge to understand *why* or *how* exactly these tricks work. Luckily, some of the more important modules do a better job at this, so overall it's not too much of a concern. I would however strongly advise people taking RTO to not take all the content at face value, and find some extra background to get a better grip on the "why, what, and how" of things. Luckily, RastaMouse gives you quite some references during the course to get you started with this.

## The Labs

The labs are a key aspect of the course, and mostly function as a sandbox environment to practice techniques discussed during the course. The practical exercises that you are required to complete during the course all take place in the labs. Some exercises are quite straight-forward and mirror the techniques discussed in the theory, others require you to really get creative with the tools and techniques that have been discussed and apply some problem-solving skills of your own.

The labs are quite strictly firewalled and hardened, so simply compromising every machine with the DA password hash and dumping all the flags is out of the question. Some machines have multiple entry points for you to practice, others have been hardened to allow you to compromise them only through a specific technique. 

Though you will see most of the labs as part of the course and exercises, I would recommend everyone to do a "clean run" after completing the exercises. There are for sure some parts of the lab that you can only discover on your own, which also gives you the opportunity get some more valuable practice in before your exam. 🙂

{{< x user="chvancooten" id="1393655024866283520" >}}

I can think of very little improvement points regarding the labs. One of my primary objections is that initial access into the labs can be finnicky at times, and it cannot be bypassed once you already gained access. This is quite annoying if the lab has been reset and you just want to re-establish beacons, only to find that the phishes you sent earlier now stopped working due to infrastructure instability. Luckily, RastaMouse has confirmed that this is something that will be fixed in the next version of the course.

If you at any point get stuck during the exercises or labs, a Slack Workspace and Canvas forum are available. I found the Slack channels to be a helpful resource with RastaMouse being very active, and quite some other folk also hanging around and being helpful. There's even a bot which auto-recognizes some error codes and tells you to migrate out of "Session 0" if you're stuck there (if you know you know 😉).

## The Exam

As per usual and for obvious reasons I cannot disclose too much about the setup or contents of the exam. In a general sense though, the exam fits the course quite well. It consists of four flags, of which you need to submit at least three to pass. You get 48 hours to submit your flags, which should in any case be plenty of time to take it easy and go through the exam labs at your own pace.

Truth be told, I was a bit disappointed at how easy the first three flags were in my version of the exam. The fourth flag however provided much more of a challenge and was a welcome change in pace from the others. It should be noted that the course is however marked as a beginner-level course, so I shouldn't complain about the difficulty too much. Obviously, there is no shame in 'only' submitting three flags to pass the exam. However, based on my experience with the exam I would say that everyone who has prior red team operations experience (either working experience or through certs like OSEP) should really challenge themselves to try and submit all four flags - it's definitely worth it! 

{{< x user="chvancooten" id="1410624406687260679" >}}

The exam doesn't require a report, which is a welcome break to some. I don't mind reporting for exams myself, and honestly it should become routine to take good and report-worthy notes in any case. So, even if it's not strictly required, my strong advice would be to challenge yourself to make a habit of keeping quality notes. If you need some inspiration, I discuss my technique for keeping quality notes and turning them into a report easily [in this blog post](https://casvancooten.com/posts/2020/05/generating-pretty-pwk-reports-with-pandoc-and-markdown-templates-inside/).

## Conclusion

The RTO course is the most practical red teaming course I have seen. Though it's a little thin on providing in-depth explanation or theory in some modules, it really sets you up with a solid toolbox and knowledge of proven tradecraft that you can start applying straight away. The labs are very qualitative and really give you the opportunity to internalize what you've learnt, as well as the opportunity for further practice. The exam is a bit easy for more experienced red teamers, but getting all four flags is a fun challenge none the less. The course comes at a much lower price point than for example Offensive Security or SANS courses, especially considering that one or two months of lab time should be enough for most. 

Overall, I would say that the course is worthwhile for almost all (aspiring) red teamers. If you already have a lot of red teaming experience the course will lose some value, but you will for sure learn a lot of new tricks and the exam can be a fun challenge nonetheless. I personally can't wait to see what RastaMouse has in store for us with the future new rendition of this course (RTO2 when?!)!