+++
title = "So You Wanna Hack a Bank? 'Global Central Bank' (PACES) Certification Review"
date = "2021-10-05"
toc = true
draft = false
type = ["posts","post"]
tags = [
    "PACES",
    "GCB",
    "Active Directory",
    "Hacking",
]

[ author ]
  name = "Cas van Cooten"
+++

## Introduction

The ["Global Central Bank" (GCB)](https://www.pentesteracademy.com/gcb) labs and accompanying "PentesterAcademy Certified Enterprise Security Specialist" (PACES) certification are definitely something else. It is more or less the "level-up" from the respective ["Attacking and Defending Active Directory" (CRTP)](https://www.pentesteracademy.com/activedirectorylab) and ["Windows Red Team Lab" (CRTE)](https://www.pentesteracademy.com/redteamlab) courses, also provided by PentesterAcademy. GCB is the hardest of the three, so if you're looking for more beginner-friendly material, you're probably better off reading [my blog post on CRTP](https://casvancooten.com/posts/2020/10/getting-the-crtp-certification-attacking-and-defending-active-directory-course-review/) instead.

PentesterAcademy calls GCB a "Cyber Range" rather than a course, and I definitely have to agree with them. The labs are the main focus of the course, followed by the certification exam. There is not much courseware included, the participant is only provided with 9 videos (totaling 3 hours) covering certain topics that are relevant in the labs. These videos only serve as a primer, as you will for sure have to do your own research when tackling the labs (or the "Cyber Range" if you're into that business lingo 😉).

## The Labs

The labs make up the bulk of the certification, and it is without a shadow of a doubt where the value lies. The lab environment is immense, covering 26 machines spread out over 9 Active Directory domains in 7 forests. The focus of the labs is exploitation of modern and hardened Windows and Active Directory environments. It is designed to be exploited manually through the RDP foothold that you get, but it's doable (and very fun) to do with a C2 framework as well.

In the labs, you will encounter a whole range of modern (security) technologies. You will come across technologies with spooky acronyms such as Local Administrator Password Solution (LAPS),  Just Enough Administration (JEA), Windows Defender Application Control (WDAC), Attack Surface Reduction (ASR), Application Whitelisting (AWL), Windows Server Update Services (WSUS), Hyper-V & Windows Subsystem for Linux (WSL), and Credential Guard (CG). Besides that, you will see "the usual" AD trickery, including delegation abuse, misconfigured privileges or ACL, roasting attacks, etcetera.

All of the above is packed into an environment that reflects that of a large and mature enterprise. A major component of this is strict firewalling, which restricts traffic between (and sometimes within) forests. It is up to you to find the holes in the firewall and jump the forest boundary by exploiting the technologies outlined above. In short: lots of fun!

Of course, a lab of this magnitude doesn't come without flaws. Several exploitation steps in the lab feel contrived and designed to showcase certain technologies, rather than mimicking real enterprise environments. This includes the firewall rules in the lab, that often feel overly restrictive to the point where it doesn't make much sense (for example a firewalled server that can reach port 80 on your foothold machine 🤔). This results in some nasty situations where you have to blindly guess which ports will be open for a reverse connection. For some steps, you also have to make other blind assumptions (e.g. phishing payloads), which can become frustrating at times.

Additionally, the lab only has one final objective. There is no split into sub-objectives or challenges like there is with CRTP and CRTE, for example. While this has the advantage of making the lab more "free-form", it also sometimes makes it a bit too unclear what the next step will be. Solid enumeration and post-exploitation methodology definitely helps gather the information that you need, but this also involves port-scanning a /16 IP range with ICMP disabled over VPN which is definitely not fun.

Despite these occasional frustrations, though, the labs are very challenging and fun to do. The numerous exploitation steps are diverse and very satisfying to complete. The lab is far from easy, and you will definitely have to ask for hints at various points (I know I did). If you are looking for a challenge lab that mimics a large enterprise environment and showcases a lot of modern technologies, the GCB labs are it.

## The Exam

The PACES certification exam is different from a lot of other course exams in that it includes two parts. The first part is compromising several machines across multiple forests by getting low- or high-privileged command execution. The second part is fixing the vulnerabilities you identified, as well as implementing some 'client requirements' that are shared in advance. In total, you get 48 hours to complete the practical part, and 48 hours after that to hand in your report.

Given all of the exciting stuff covered in the labs, the exploitation part of the exam felt a bit bland. The exploitation steps are way easier than those in the labs, and not as much fancy technologies are brought out to play. Because of this, it feels more or less the same as the CRTP or CRTE exams, where you use your low-privileged RDP foothold to escalate your privileges and move laterally (not necessarily in that order), as well as jump the forest boundary by abusing AD misconfigurations. 

The mitigation part however was a lot of fun to do. Fixing vulnerabilities is definitely not something I'm used to doing, so it was a nice change of pace from the other certs I've done. For this part of the exam you will be rummaging around on target computers and domain controllers to patch the issues you identified and implement some specific features as requested by the "client". Nothing you do in this part of the exam will be very hard, but it will definitely help solidify your understanding of certain technologies.

To achieve the PACES certification, an exam report has to be submitted. This report should extensively discuss both the exploitation and mitigation parts in such a way that your thought process is clear and your steps are reproducible. I (again) used a similar approach to the one described in [this blog post](https://casvancooten.com/posts/2020/05/generating-pretty-pwk-reports-with-pandoc-and-markdown-templates-inside/), drafting my exploitation and remediation notes in Markdown and converting them to a pretty report after completing the exam. This way, creating the exam report didn't cost a lot of time beyond the hours spent in the labs. 

In total, I spent about 8 hours in the exam labs for the exploitation and remediation parts, and compiling the report took me approximately two more hours on top of that. I can see some rabbit holes taking more time, but 48 hours for the practical part of the exam should be more than plenty in most cases!

## The Verdict

Overall, the exam was fun to do but the offensive part was a bit of a letdown. It feels like the exam could have been quite a bit more challenging if the requirement "you have to fix everything you abuse" was dropped. The main part of GCB is for sure the labs, and because of that I'm not sure if the PACES certification "proves" a lot of skill if one didn't complete the labs. Overall though, GCB is very fun to do and the PACES certification is a nice cherry on top. Let's see if PentesterAcademy will come up with an even more challenging lab in the future (looking at you Nikhil 😁)!