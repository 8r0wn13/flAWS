# Write up for flaws.cloud by Scott Piper - Hacking the cloud

### Requirements
Create an AWS S3 account<br>
Install aws s3<br>
&emsp;`$ curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"`<br>
&emsp;`$ unzip awscliv2.zip`<br>
&emsp;`$ sudo ./aws/install`<br>

### Description
Through a series of levels you'll learn about common mistakes and gotchas when using Amazon Web Services (AWS). There are no SQL injection, XSS, buffer overflows, or many of the other vulnerabilities you might have seen before. As much as possible, these are AWS specific issues.

A series of hints are provided that will teach you how to discover the info you'll need. If you don't want to actually run any commands, you can just keep following the hints which will give you the solution to the next level. At the start of each level you'll learn how to avoid the problem the previous level exhibited.

Scope: Everything is run out of a single AWS account, and all challenges are sub-domains of flaws.cloud. 

---

### Personal note
I did the exercises without using the  hints and only included the hints after I solved a level.<br>
To avoid any spoilers, hints are closed by default, but are there if you need them

---

## Level 1
This level is *buckets* of fun. See if you can find the first sub-domain.

<details closed>
<summary>Hint 1</summary>
This is a hint
</details>

### My solution
Find out if flaws.cloud is using AWS S3
When resolving the flaws.cloud with nslookup, it will provide multiple ip addresses<br>
`$ nslookup flaws.cloud`
```
Non-authoritative answer:
Name:	flaws.cloud
Address: 52.218.128.127
Name:	flaws.cloud
Address: 52.92.178.75
Name:	flaws.cloud
Address: 52.92.211.123
Name:	flaws.cloud
Address: 52.218.208.211
Name:	flaws.cloud
Address: 52.92.133.171
Name:	flaws.cloud
Address: 52.92.195.115
Name:	flaws.cloud
Address: 52.92.137.171
Name:	flaws.cloud
Address: 52.92.212.91
```
By performing another nslookup on the IP address, it will perform a reverse domain lookup `$ nslookup 52.218.128.127`
```
127.128.218.52.in-addr.arpa	name = s3-website-us-west-2.amazonaws.com.
```
Now we know for sure, flaws.cloud is hosted in a S3 bucket on AWS<br>
With AWS command line, we can navigate to flaws.cloud and use certain commands<br>
To see what files are at flaws.cloud `$ aws s3 ls s3://flaws.cloud --no-sign-request`
> --no-sign-request is needed to avoid checking for credentials

```
2017-03-14 04:00:38       2575 hint1.html
2017-03-03 05:05:17       1707 hint2.html
2017-03-03 05:05:11       1101 hint3.html
2020-05-22 20:16:45       3162 index.html
2018-07-10 18:47:16      15979 logo.png
2017-02-27 02:59:28         46 robots.txt
2017-02-27 02:59:30       1051 secret-dd02c7c.html
```
There is a file secret-dd02c7c.html file<br>
Download the file to the local machine `$ aws s3 cp s3://flaws.cloud/secret-dd02c7c.html ./ --no-sign-request`
```
download: s3://flaws.cloud/secret-dd02c7c.html to ./secret-dd02c7c.html
```
Open the file `$ open secret-dd02c7c.html`
As it is an html file, the file will automatically open in the default browser, showing the secret file has been found and giving access to the second level!
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://github.com/8r0wn13/flAWS/assets/37810593/7c1b5e96-99f0-436b-a433-3b94b0b3fdcb">
  <source media="(prefers-color-scheme: light)" srcset="https://github.com/8r0wn13/flAWS/assets/37810593/7c1b5e96-99f0-436b-a433-3b94b0b3fdcb">
  <img alt="Shows an illustrated sun in light mode and a moon with stars in dark mode." src="https://github.com/8r0wn13/flAWS/assets/37810593/7c1b5e96-99f0-436b-a433-3b94b0b3fdcb">
</picture>

---

## Level 2
This level is *buckets* of fun. See if you can find the first sub-domain.

<details closed>
<summary>Hint 1</summary>
This is a hint
</details>
