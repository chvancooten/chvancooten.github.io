+++
title = "Try Harder: Yet Another Journey To OSCP"
date = "2020-05-17"
toc = true
draft = false
type = ["posts","post"]
series = ["OSCP"]
tags = [
    "PWK",
    "OSCP",
    "Hacking",
]

[ author ]
  name = "Cas van Cooten"
+++

*The first part of this blog post dives into my personal OSCP story. If you're only interested in stuff you can apply to your own PWK journey, jump to the [key takeaways](#takeaways) or the [OSCP FAQ](#oscp-faq).*

## Preamble

I don't have a very technical background. I did a Master's in Information Science before starting as a Cyber Security Consultant. In my current role, I deal with various cyber topics on an organizational level - usually not from a very technical perspective. 

As such, when a couple of colleagues were planning to enroll in PWK and go for the OSCP certification together, my plan was initially to "just tag along". That turned out a bit differently! In the week of writing this blog post, I was informed that I passed the PWK exam and have obtained the OSCP certification. In this post, I'll outline my journey from script kiddie to *certified* script kiddie!

## Act I - Humble Beginnings

My investment in hacking started with an "OSCP preparation day", organized by said colleagues late last year. During this day, pretty much all we did was get together and own some [Hack The Box](https://www.hackthebox.eu/) machines that are similar to OSCP. I had some experience with hacking from earlier courses and one or two HTB machines, but this practice day really sparked my interest in improving my `1337 h4ck1ng sk1llz`. 

From that point, I was motivated to start practicing my skills through HTB. I started with some active machines, but since the learning curve for these is usually quite steep I quickly purchased a VIP subscription. My main guide from that point was [TJ_Null's "OSCP-like" machines list](https://docs.google.com/spreadsheets/d/1dwSMIAPIam0PuRBkCiDI88pU3yzrqqHkDtBngUHNCw8/edit#gid=1839402159). Of course, I would also have a look at newly released machines now and then. A man needs that HTB rank!

> If you're interested, you can find my HTB machine progression [here](https://www.hackthebox.eu/profile/73268). My favorite machine from that time is probably [Forest](https://www.hackthebox.eu/home/machines/profile/212). It took me quite some time and effort to complete back then, but really did introduce me to Windows and Active Directory hacking concepts.

At this point, I was still convinced I would probably never make OSCP and was just tagging along for the ride. However, hacking HTB machines really felt like a hobby rather than work, and my evening and weekend hours on learning new hacking tricks really energized me. Slowly but surely, I realized I was actually getting kind of good at this!

## Act II - Getting Real

Over time, I was getting more and more dedicated to practice with HTB in my evenings and weekends. In the three months following up the initial practice day, I had completed approximately 50 HTB machines, ranging from easy to hard difficulty. Through HTB, I can now say I have learned many hacking techniques and tricks that would later prove invaluable. Even more so, I had gotten comfortable with the underlying concepts and technologies that were so foreign to me when I started. 

By the end of January (about three months in), some colleagues had convinced me to take the plunge and just go for it. Since my employer agreed to pay for the costs of PWK (a *very* big plus), I decided to enroll in PWK with a mid-February start date. Since I enrolled just before the announcement of the [2020 version](https://www.offensive-security.com/offsec/pwk-2020-update/) of the PWK course, Offensive Security got me an upgrade to that version, which was awesome!

## Act III - Working Through the Labs

By the time my PWK labs started, I was super hyped to jump in. Given my background, my game plan was to start by going through the course materials first, finishing the PDF and exercises before jumping into the labs. I did however run some recon and pop an easy machine or two at the start of my time, just to get a feel for the labs.

Forcing myself to finish the PDF before jumping into the labs helped me to keep motivated in going through the theory, which can definitely feel like a long road. There's a *lot* of content in the new PDF - it's 853 pages long versus 380 pages in the old PWK. Not all chapters are equally engaging, so this part will require some dedication and focus from your side. To find a balance between soaking up the theory and applying it in practice, I would do exercises as they popped up in the PDF (at the end of every chapter). 

Completing the PDF and exercises took me about two weeks altogether. I decided to leave the videos for what they were, since I felt like the PDF did a better job explaining the content matter. Additionally, I just wanted to jump into the labs at this point!

> Note that you're not required to complete the course exercises, but if you hand them in together with a lab report you can earn 5 bonus points for your exam. I chose to do this, not necessarily because of the bonus points, but rather because it's good for practice anyway!

As circumstance would have it, the Corona crisis kicked in a couple of weeks into my lab time. Since I mostly had to fit in PWK next to my 40-hour workweek, this actually proved to be a silver lining to the whole situation. All social and work events were pretty much cancelled, which gave me additional time to practice in my evenings and weekends.

I didn't really have a specific strategy for tackling the labs. I would run recon on the entire range of the initial subnet, picking off machines that looked like 'quick wins' (interesting web applications or file shares, known vulnerable or legacy service versions, etc.) first. Eventually, I ran into hosts that had access to new subnets, giving me access to those as well. Unfortunately I can't disclose the specifics of machines or subnets for obvious reasons, but tackling all the boxes was a fun ride that taught me a lot of new skills!

Towards the end of the labs (about 10 to 5 machines left) I would get gradually more stuck. At this point I would turn to the forums for help. Though I would generally recommend staying away from the forums as much as possible, some posts on the forums do help in finding the right path or identifying the right technique, without spoiling too much. As such, the forums may be a nice 'last resort' when you really get stuck on a machine!

The below *very scientific graph*™ shows my lab completion over time, from the first to the last machine (there are 67 in total in the 2020 labs). As shown, it took me a bit under 2 months (including approximately 2 weeks of PDF/exercise time) to complete 100% of the labs. Note that even though I only had my evenings, my weekends, and occasionally a full day to spare, that is not to say I didn't spend much time on rooting the entire lab environment. If I had to put an hour estimate on it, I would say I probably spent around 175 hours in the labs in total.
 
![PWK Lab Progression](/images/pwk-lab-progression.png) 

Overall, the labs were definitely the coolest part of the course. Though I did complete 100% of the labs, that is in no way necessary for passing the exam. If you are short on time I would definitely recommend focusing on really understanding the course materials over completing every machine in the labs. That said, if you manage to complete 100% of the labs within your course time chances are you are well prepared for the exam!

## Act IV - The Final Countdown

Since I had a week or two between completing the labs and my scheduled exam date, I decided to practice some more. At a slightly slower pace, I went on to complete the HTB machines I had left from TJ_Null's list. As they were mostly machines labeled "harder than OSCP, but good practice", some of them were a lot tougher than the labs. I do agree most of them are great practice, though!

I also spent some time before the exam preparing my lab report, and in doing so establishing a process for my exam report as well. Since I had already documented my machines in accordance with a predefined template (more details in [this blog post](https://cas.vancooten.com/posts/2020/05/generating-pretty-pwk-reports-with-pandoc-and-markdown-templates-inside/)), most effort was spent preparing the overall report templates and styling process. As mentioned in my earlier blog, I shared those on [GitHub](https://github.com/chvancooten/OSCP-MarkdownReportingTemplates) - hopefully they will be useful for someone else down the road!

In the final days leading up to the exam, I took some days off and started working on a tighter schedule. Three days in advance, I scheduled a day of Buffer Overflow practice. Since this part of the exam was supposed to be fairly straightforward, I wanted to really get comfortable with the required steps for developing a basic BoF exploit. To practice, I used the executables discussed during the course and from the labs (there's several binaries), as well as the `TRUN` overflow for [VulnServer](https://github.com/stephenbradshaw/vulnserver) and [Brainpan from Vulnhub](https://www.vulnhub.com/entry/brainpan-1,51/). After running through the process a couple of times, I was pretty comfortable with all the steps and confident in the BoF part of the exam.

Two days in advance, I had planned to do a "practice exam". There's a collection of OSCP-like VulnHub machines compiled into a "practice exam" [here](https://h4cklife.wordpress.com/2018/05/22/a-pre-exam-for-future-oscp-students/), which did sound interesting. Unfortunately, I had some technical issues preventing me from starting up one of the machines. In the end, I ended up rooting the four working machines, which gave me some confidence for the exam even though it didn't really provide an "exam-like" experience.

The day before the exam I had scheduled... nothing. I thought it would be good to clear my head and be away from the computer screen for a day, which is what I did! I took a long walk and hit the hay early. A long day would be ahead.

## Act V - Twenty-four Hours

Finally, the day of my exam had arrived. I was nervous, but looking forward to it at the same time. I had decided to start with the BoF right away to -hopefully- net a quarter of the points in a short time and lose some of the nerves. I did, and it played out perfectly. It took me about 40 minutes to complete and document the Buffer Overflow, and that's including some technical difficulties with the target system. 25 points were in!

Afterwards, I decided to channel my adrenaline rush on the 25 point machine. For some reason, it was a *really* easy exploit path. I was probably lucky in dodging some rabbit holes, which is what the 25-pointer is usually notorious for. Again, the exploit didn't take me that much effort and 1 hour and 15 minutes into my exam, I had rooted the 25 pointer. I really couldn't believe I was already 50 points in, and felt almost invincible at this point!

After that, I started looking at the remaining machines, but I got stuck. For several hours, I couldn't find *any* entry vector into the remaining three machines. I started stressing out a bit, even though I still had plenty of time on the clock. After some time, I found the entry vector to one of the 20-pointers. The exploit from that point wasn't too difficult, and after 6 hours and 10 minutes, I had reached the passing grade of 70 points.

It felt like a weight fell of my shoulders. My practice had paid off, and I could spend the rest of my exam time trying to get 100 points. This stress release helped clear my head, and before long I had found the entry point to the other 20-pointer. 8 hours and 21 minutes in, I had 90 points under my belt.

I was almost euphoric, and convinced I would easily get the 10-pointer after seeing the rest of the boxes. However, for some reason the last box was *freaking impossible*. I ended up running into dead ends for about 8 hours, until I decided the 10 points probably weren't worth it. At midnight, I tapped out to hit the hay.

Again, it's too bad I can't share any specifics regarding the machines that I faced. As mentioned however, I do think that if you can compromise the majority of lab machines with confidence, and/or have done most OSCP-like HTB machines with little to no help, you should be able to get 70 points without any major issues. In the end, the exam is mostly about showing that you understand the various methods and are able to adapt, more so than it is about having kick-ass technical skills.

I handed in my exam and lab reports the afternoon after my exam, and OffSec was pretty quick in relieving me of all doubt. Three workdays after my exam, I received the message that I had worked so many hours towards getting. I did it!

![PWK Lab Progression](/images/pwk-pass.jpg) 

## Takeaways

I hope the above story was at least slightly interesting to read, and that perhaps you can take away some learnings for your own OSCP journey. Perhaps it will even inspire someone to take the plunge and enroll in PWK! 

Since I learned a lot from going through the "zero to OSCP" journey myself, I wanted to note down some of the points I encountered during my last couple of months.

- Motivation and dedication are key. You will have to spend a lot of time on OSCP prep, so you better make sure you actually enjoy the process of doing so! If you're not dedicated or motivated to get through the materials, you're gonna have a bad time.
- There is no single 'golden bullet' to OSCP preparations. Many people will offer varying pieces of advice - find what works for you.
- There are plenty of sites out there that you can use to practice at little to no cost (Hack The Box, Vulnhub, TryHackMe, ...). If you don't have a technical background, practicing for a couple of months will definitely help you nail OSCP. These platforms are also great if you currently don't have the means to pay for PWK.
- Restrain yourself from looking at hints right away when you get stuck. The pain of wasting several hours on a box doing something stupid will keep you from ever doing it again.
- OSCP is not about having great technical skills. It's about the foundational mindset you need to become a good hacker. This is especially true for the certification exam.
- Nailing all the lab machines is cool to do, but not at all required for passing OSCP. The same goes for handing in the lab report and exercises for bonus points (see [below](#oscp-faq)).
- Write down everything you do in a note-keeping app of your choosing, and make sure it's searchable. It *will* be helpful later (this doesn't just apply to OSCP, it also applies to keeping notes and writeups in general).

## OSCP FAQ

Since I see a lot of posts on Reddit and Twitter with recurrent questions regarding PWK / OSCP, I figured I'd close this post with a "PWK FAQ". Note that the given answers are my personal take, and there are likely to be different and equally valid answers to your question out there. If you have a question that's missing from the list, don't hesitate to let me know on [Twitter](https://twitter.com/chvancooten)!

**I want to go for OSCP but I'm unsure because of reason X. Should I do it?**

Yes.

**How much lab time should I buy?**

It depends on your current skill level, your game plan, and the time you can spend. Generally, I would say two to three months, depending on your experience level. If you're a seasoned pentester and/or have 8+ hours a day to spend on your PWK studies, one month might be enough.

**My game plan for OSCP is X. Is that okay?**

Generally, the answer will be yes. As long as you have thought about your approach, the time you are able to spend, and how it'll fit into your personal life the coming months, you will probably be fine.

**I don't have a game plan. How should I approach becoming OSCP?**

If you don't have a game plan at all, consider the following approach. I personally feel that this approach should generally work for most people. 

- First, plan 1 to 3 months of HTB practice, completing retired boxes from [TJ_Null's "OSCP-like" machines list](https://docs.google.com/spreadsheets/d/1dwSMIAPIam0PuRBkCiDI88pU3yzrqqHkDtBngUHNCw8/edit#gid=1839402159). Take to the HTB forums or e.g. [Ippsec's YouTube channel](https://www.youtube.com/channel/UCa6eh7gCkpPo5XXUDfygQQA) if you hit a wall. 
- Once you're comfortable rooting easy-medium boxes, enroll in PWK with 3 months of lab time. This will give you plenty of time to go through the PDF and exercises, as well as spend enough time in the labs. 
- Plan the exam if you're ready during or after your lab time, practice some more if you're not (there's no rush!). 

**What's the best way to spend your lab time?**

Though it may be tempting to jump right into the lab when your course time starts, I do think you will get the most value out of your lab machines if you go through the PWK PDF and exercises first. It takes some time, but will help you really build a foundation and understanding of the topics that are addressed in the lab. That being said, everyone has their own style and preferences - as such there is likely no "best" way to spend your lab time.

**Is it worth doing that reporting and all those exercises for 5 bonus points?**

Considering the effort required for completing the exercises (especially for PWK 2020) and the lab report, the answer to the question is probably no. That said, the bonus points are not the reason you should go through the exercises and lab reporting - you should definitely do that for yourself. I personally took a lot out of doing the exercises, but skipping (some of) them is a perfectly valid decision as well. 

**Will the course materials teach me everything I need for the labs/exam?**

No. The course materials will give you a solid foundation, and help you establish a methodology for learning new stuff (in other words: Google). That said, the PWK PDF likely won't contain the solution for your exam machines - it's all up to you to practice, get comfortable with the provided methods, and `try harder`!

**When will I be ready for the exam?**

Whenever you feel ready! I know it's a cliché, but the PWK exam is more about having confidence in your skills and keeping your head cool than it is about deep-technical skills. Don't let the fact that you didn't complete 100% of the labs or are still unsure about that one machine stop you. 

**I have the old PWK version, should I upgrade to the 2020 version?**

If you already progressed through the 'old' labs, I wouldn't bother. If you're at the start of your PWK course and still need to go through the PDF, do it. It provides more background into existing topics, as well as a lot of new content (e.g. Active Directory exploitation). 