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

![alt text](https://github.com/8r0wn13/flAWS/blob/main/images/level2.png?raw=true)

#### Lesson learned
On AWS you can set up S3 buckets with all sorts of permissions and functionality including using them to host static files. A number of people accidentally open them up with permissions that are too loose. Just like how you shouldn't allow directory listings of web servers, you shouldn't allow bucket listings.

##### Examples of this problem
&emsp;Directory listing of S3 bucket of Legal Robot (link) and Shopify (link).
&emsp;Read and write permissions to S3 bucket for Shopify again (link) and Udemy (link). This challenge did not have read and write permissions, as that would destroy the challenge for other players, but it is a common problem. 

#### Avoiding the mistake
By default, S3 buckets are private and secure when they are created. To allow it to be accessed as a web page, I had turn on "Static Website Hosting" and changed the bucket policy to allow everyone "s3:GetObject" privileges, which is fine if you plan to publicly host the bucket as a web page. But then to introduce the flaw, I changed the permissions to add "Everyone" to have "List" permissions. 

![alt text](https://github.com/8r0wn13/flAWS/blob/main/images/everyone.png?raw=true)

"Everyone" means everyone on the Internet. You can also list the files simply by going to http://flaws.cloud.s3.amazonaws.com/ due to that List permission.

## Level 2
### Description
The next level is fairly similar, with a slight twist. You're going to need your own AWS account for this. You just need the free tier.

<details closed>
<summary>Level 2: Hint 1</summary>
You need your own AWS key, and you need to use the AWS CLI. Similar to the first level, you can discover that this sub-domain is hosted as an S3 bucket with the name "level2-c8b217a33fcf1f839f6f1f73a00a9ae7.flaws.cloud".

Its permissions are too loose, but you need your own AWS account to see what's inside. Using your own account you can run:

`aws s3 --profile YOUR_ACCOUNT ls s3://level2-c8b217a33fcf1f839f6f1f73a00a9ae7.flaws.cloud`

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

![alt text](https://github.com/8r0wn13/flAWS/blob/main/images/level3.png?raw=true)

#### Lesson learned
On AWS you can set up S3 buckets with all sorts of permissions and functionality including using them to host static files. A number of people accidentally open them up with permissions that are too loose. Just like how you shouldn't allow directory listings of web servers, you shouldn't allow bucket listings.

##### Examples of this problem
&emsp;Directory listing of S3 bucket of Legal Robot (link) and Shopify (link).
&emsp;Read and write permissions to S3 bucket for Shopify again (link) and Udemy (link). This challenge did not have read and write permissions, as that would destroy the challenge for other players, but it is a common problem. 

#### Avoiding the mistake
By default, S3 buckets are private and secure when they are created. To allow it to be accessed as a web page, I had turn on "Static Website Hosting" and changed the bucket policy to allow everyone "s3:GetObject" privileges, which is fine if you plan to publicly host the bucket as a web page. But then to introduce the flaw, I changed the permissions to add "Everyone" to have "List" permissions. 

![alt text](https://github.com/8r0wn13/flAWS/blob/main/images/authenticated_users.png?raw=true)

"Everyone" means everyone on the Internet. You can also list the files simply by going to http://flaws.cloud.s3.amazonaws.com/ due to that List permission. 

## Level 3
### Description
The next level is fairly similar, with a slight twist. Time to find your first AWS key! I bet you'll find something that will let you list what other buckets are.

<details closed>
<summary>Level 3: Hint 1</summary>
Like the first level, you should have figured out how to list the files in this directory, and seen that listing in this bucket is open to "Everyone". See the file listing at level3-9afd3927f195e10225021a578e6f78df.flaws.cloud.s3.amazonaws.com/

This S3 bucket has a .git file. There are probably interesting things in it. Download this whole S3 bucket using:

`aws s3 sync s3://level3-9afd3927f195e10225021a578e6f78df.flaws.cloud/ . --no-sign-request --region us-west-2`

</details>

### My solution Level 3
We giving the following command `$ aws s3 ls --profile dennis s3://level3-9afd3927f195e10225021a578e6f78df.flaws.cloud/` it will return:
```
                           PRE .git/
2017-02-27 01:14:33     123637 authenticated_users.png
2017-02-27 01:14:34       1552 hint1.html
2017-02-27 01:14:34       1426 hint2.html
2017-02-27 01:14:35       1247 hint3.html
2017-02-27 01:14:33       1035 hint4.html
2020-05-22 20:21:10       1861 index.html
2017-02-27 01:14:33         26 robots.txt
```
There is no secret file, however there is a .git file<br>
Git is used for versioning and it can be that keys were used in previous versions.<br>
All history can be synced instead of copied as done before:<br>
`$ aws s3 sync --profile dennis s3://level3-9afd3927f195e10225021a578e6f78df.flaws.cloud/ ./level3`

Go to directory to the git directory `$ cd level3/.git` and type `$ tree`<br>
![alt text](https://github.com/8r0wn13/flAWS/blob/main/images/tree.png?raw=true)

We can go through all of the files manually, but we can also guess based on logic.<br>
Git uses has a master branch and can have sub-branches<br>
In `log/refs/heads` there is a master file, hence read that file `$ cat logs/refs/heads/master`
```
0000000000000000000000000000000000000000 f52ec03b227ea6094b04e43f475fb0126edb5a61 0xdabbad00 <scott@summitroute.com> 1505661007 -0600	commit (initial): first commit
f52ec03b227ea6094b04e43f475fb0126edb5a61 b64c8dcfa8a39af06521cf4cb7cdce5f0ca9e526 0xdabbad00 <scott@summitroute.com> 1505661043 -0600	commit: Oops, accidentally added something I shouldn't have
````
The second line shows that the developer "accidentitally added something he/she shouldn't have", hence this is commit can be interesting.<br>
`f52ec03b227ea6094b04e43f475fb0126edb5a61` is the hash for that commit and which can be checked out `$ git checkout f52ec03b227ea6094b04e43f475fb0126edb5a61`<br>
This command shows the code from the past `$ ls`
```
access_keys.txt          hint1.html  hint3.html  index.html
authenticated_users.png  hint2.html  hint4.html  robots.txt
```
Now there is a new file `access_keys.txt`. Read that file `$ cat access_keys.txt`
```
access_key AKIAJ366LIPB4IJKT7SA
secret_access_key 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
```
These are access keys, which make it possible to access the application as the user connected to these access keys.<br>
Create a new profile `$ aws configure --profile unknown_user`
```
AWS Access Key ID [None]: AKIAJ366LIPB4IJKT7SA
AWS Secret Access Key [None]: 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
Default region name [None]: 
Default output format [None]:
```
Now try to access the web page for level 3 again, with this newly created profile `$ aws s3 ls --profile unknown_user s3://level3-9afd3927f195e10225021a578e6f78df.flaws.cloud`
```
                           PRE .git/
2017-02-27 01:14:33     123637 authenticated_users.png
2017-02-27 01:14:34       1552 hint1.html
2017-02-27 01:14:34       1426 hint2.html
2017-02-27 01:14:35       1247 hint3.html
2017-02-27 01:14:33       1035 hint4.html
2020-05-22 20:21:10       1861 index.html
2017-02-27 01:14:33         26 robots.txt
```
There is no difference with before.<br>
When no URL is provided with the aws s3 command, it wil list all buckets the unknown_user has access to `$ aws s3 ls --profile unknown_user`
```
2017-02-12 22:31:07 2f4e53154c0a7fd086a04a12a452c2a4caed8da0.flaws.cloud
2017-05-29 18:34:53 config-bucket-975426262029
2017-02-12 21:03:24 flaws-logs
2017-02-05 04:40:07 flaws.cloud
2017-02-24 02:54:13 level2-c8b217a33fcf1f839f6f1f73a00a9ae7.flaws.cloud
2017-02-26 19:15:44 level3-9afd3927f195e10225021a578e6f78df.flaws.cloud
2017-02-26 19:16:06 level4-1156739cfb264ced6de514971a4bef68.flaws.cloud
2017-02-26 20:44:51 level5-d2891f604d2061b6977c2481b0c8333e.flaws.cloud
2017-02-26 20:47:58 level6-cc4c404a8a8b876167f5e70a7d8c9880.flaws.cloud
2017-02-26 21:06:32 theend-797237e8ada164bf9f12cebf93b282cf.flaws.cloud
```
Above are all the s3 buckets the unknown_user has access to<br>
The goal is to get to level 4, hence open the link `http://level4-1156739cfb264ced6de514971a4bef68.flaws.cloud`


#### Lesson learned
People often leak AWS keys and then try to cover up their mistakes without revoking the keys. You should always revoke any AWS keys (or any secrets) that could have been leaked or were misplaced. Roll your secrets early and often.

##### Examples of this problem

&emsp;Instagram's Million Dollar Bug: In this must read post, a bug bounty researcher uncovered a series of flaws, including finding an S3 bucket that had .tar.gz archives of various revisions of files. One of these archives contained AWS creds that then allowed the researcher to access all S3 buckets of Instagram. For more discussion of how some of the problems discovered could have been avoided, see the post "Instagram's Million Dollar Bug": Case study for defense 

Another interesting issue this level has exhibited, although not that worrisome, is that you can't restrict the ability to list only certain buckets in AWS, so if you want to give an employee the ability to list some buckets in an account, they will be able to list them all. The key you used to discover this bucket can see all the buckets in the account. You can't see what is in the buckets, but you'll know they exist. Similarly, be aware that buckets use a global namespace meaning that bucket names must be unique across all customers, so if you create a bucket named `merger_with_company_Y` or something that is supposed to be secret, it's technically possible for someone to discover that bucket exists.

#### Avoiding this mistake
Always roll your secrets if you suspect they were compromised or made public or stored or shared incorrectly. Roll early, roll often. Rolling secrets means that you revoke the keys (ie. delete them from the AWS account) and generate new ones. 

## Level 4
### Description
For the next level, you need to get access to the web page running on an EC2 at 4d0cf09b9b2d761a7d87be99d17507bce8b86f3b.flaws.cloud

It'll be useful to know that a snapshot was made of that EC2 shortly after nginx was setup on it. 

<details closed>
<summary>Level 4: Hint 1</summary>
Hint for level 4
</details>

### My solution Level 4






<<To be continued, problems with my AWS account>>
