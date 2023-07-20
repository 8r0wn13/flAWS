# Write up for flaws.cloud by Scott Piper - Hacking the cloud
> Scott Piper created this challenge and therefore all credits (including the screenshots he/I made) should go to him.<br>
I am thankful Scott created this challenge and I was able to practice with it, especially the explanations after solving a level to have better understanding of where the misconfiguration(s) occured.<br>

> Personal note: I did the exercises without using the  hints and only included them after I solved a level.<br>
To avoid any spoilers, hints are closed by default, but available if you need them.<br>
Try to solve the levels without the hints in order to have the biggest learning effect :-)

### Requirements
Create an AWS S3 account (free)<br>
Install aws s3 cli<br>
&emsp;`$ curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"`<br>
&emsp;`$ unzip awscliv2.zip`<br>
&emsp;`$ sudo ./aws/install`<br>

## Level 1
### Description
Through a series of levels you'll learn about common mistakes and gotchas when using Amazon Web Services (AWS). There are no SQL injection, XSS, buffer overflows, or many of the other vulnerabilities you might have seen before. As much as possible, these are AWS specific issues.

A series of hints are provided that will teach you how to discover the info you'll need. If you don't want to actually run any commands, you can just keep following the hints which will give you the solution to the next level. At the start of each level you'll learn how to avoid the problem the previous level exhibited.

Scope: Everything is run out of a single AWS account, and all challenges are sub-domains of flaws.cloud. 

This level is *buckets* of fun. See if you can find the first sub-domain.

<details closed>
<summary>Level 1: Hint 1</summary>

The site flaws.cloud is hosted as an S3 bucket. This is a great way to host a static site, similar to hosting one via github pages. Some interesting facts about S3 hosting: When hosting a site as an S3 bucket, the bucket name (flaws.cloud) must match the domain name (flaws.cloud). Also, S3 buckets are a global name space, meaning two people cannot have buckets with the same name. The result of this is you could create a bucket named apple.com and Apple would never be able host their main site via S3 hosting.

You can determine the site is hosted as an S3 bucket by running a DNS lookup on the domain, such as:

dig +nocmd flaws.cloud any +multiline +noall +answer<br>
\# Returns:<br>
\# flaws.cloud.            5 IN A  54.231.184.255<br>

Visiting 54.231.184.255 in your browser will direct you to https://aws.amazon.com/s3/

So you know flaws.cloud is hosted as an S3 bucket.

You can then run:

nslookup 54.231.184.255<br>
\# Returns:<br>
\# Non-authoritative answer:<br>
\# 255.184.231.54.in-addr.arpa     name = s3-website-us-west-2.amazonaws.com

So we know it's hosted in the AWS region us-west-2

Side note (not useful for this game): All S3 buckets, when configured for web hosting, are given an AWS domain you can use to browse to it without setting up your own DNS. In this case, flaws.cloud can also be visited by going to http://flaws.cloud.s3-website-us-west-2.amazonaws.com/

What will help you for this level is to know its permissions are a little loose. 
</details>

### My solution Level 1
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

![alt text](https://github.com/8r0wn13/flAWS/images/level2.png?raw=true)

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://github.com/8r0wn13/flAWS/images/level2.png">
  <source media="(prefers-color-scheme: light)" srcset="https://github.com/8r0wn13/flAWS/images/level2.png">
  <img alt="Shows an illustrated sun in light mode and a moon with stars in dark mode." src="https://github.com/8r0wn13/flAWS/images/level2.png">
</picture>

#### Lesson learned
On AWS you can set up S3 buckets with all sorts of permissions and functionality including using them to host static files. A number of people accidentally open them up with permissions that are too loose. Just like how you shouldn't allow directory listings of web servers, you shouldn't allow bucket listings.

**Examples of this problem**
&emsp;Directory listing of S3 bucket of Legal Robot (link) and Shopify (link).
&emsp;Read and write permissions to S3 bucket for Shopify again (link) and Udemy (link). This challenge did not have read and write permissions, as that would destroy the challenge for other players, but it is a common problem. 

**Avoiding the mistake**
By default, S3 buckets are private and secure when they are created. To allow it to be accessed as a web page, I had turn on "Static Website Hosting" and changed the bucket policy to allow everyone "s3:GetObject" privileges, which is fine if you plan to publicly host the bucket as a web page. But then to introduce the flaw, I changed the permissions to add "Everyone" to have "List" permissions. 


<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://github.com/8r0wn13/flAWS/assets/37810593/d6d9cc9c-b876-4032-88f9-95bf55a2f317">
  <source media="(prefers-color-scheme: light)" srcset="https://github.com/8r0wn13/flAWS/assets/37810593/d6d9cc9c-b876-4032-88f9-95bf55a2f317">
  <img alt="Shows an illustrated sun in light mode and a moon with stars in dark mode." src="https://github.com/8r0wn13/flAWS/assets/37810593/d6d9cc9c-b876-4032-88f9-95bf55a2f317">
</picture>

"Everyone" means everyone on the Internet. You can also list the files simply by going to http://flaws.cloud.s3.amazonaws.com/ due to that List permission.

## Level 2
### Description
The next level is fairly similar, with a slight twist. You're going to need your own AWS account for this. You just need the free tier.

<details closed>
<summary>Level 2: Hint 1</summary>
This is a hint
</details>

### My solution Level 2
When looking at the address provided after solving level 1 we get an AccessDenied message
`$ aws s3 ls s3://level2-c8b217a33fcf1f839f6f1f73a00a9ae7.flaws.cloud --no-sign-request`

```
An error occurred (AccessDenied) when calling the ListObjectsV2 operation: Access Denied
```
This means, the address cannot be accessed anonymous like in level 1 and a valid AWS is required
Try to do the same but your AWS account `$ aws s3 ls --profile <<s3 username>> s3://level2-c8b217a33fcf1f839f6f1f73a00a9ae7.flaws.cloud`

```
2017-02-27 03:02:15      80751 everyone.png
2017-03-03 04:47:17       1433 hint1.html
2017-02-27 03:04:39       1035 hint2.html
2017-02-27 03:02:14       2786 index.html
2017-02-27 03:02:14         26 robots.txt
2017-02-27 03:02:15       1051 secret-e4443fc.html
```
It shows a secret-e4443fc.html file<br>
Download this file `$ aws s3 cp --profile <<s3 username>> s3://level2-c8b217a33fcf1f839f6f1f73a00a9ae7.flaws.cloud/secret-e4443fc.html ./`
Open the file `open secret-e4443fc.html`



<<To be continued, problems with my AWS account>>
