## AWS_task2
### Task Description:-
1. Create Security group which allow the port 80.
2. Launch EC2 instance.
3. In this Ec2 instance use the existing key or provided key and security group which we have created in step 1.
4. Launch one Volume using the EFS service and attach it in your vpc, then mount that volume into /var/www/html
5. Developer have uploded the code into github repo also the repo has some images.
6. Copy the github repo code into /var/www/html
7. Create S3 bucket, and copy/deploy the images from github repo into the s3 bucket and change the permission to public readable.
8 Create a Cloudfront using s3 bucket(which contains images) and use the Cloudfront URL to  update in code in /var/www/html

### We have to follow the given steps in order to do the task:-
#### Step 1.
In the first step you have to declare your provider and its necessary login credentials, example:-
```
provider "aws" {
  region     = "ap-south-1"
  profile    = "abhi"
}
```
#### Step 2 "Creating a security group".
In the second step you have to create a security group which allows port number 80, which in turns provide the services for HTTP protocol and port number 22 which provides services for SSH protocol. Egress is not open for all IP's and all ports. Also, CIDR is configured for IPv4 not for IPv6. The following commands will perform the above query:-
```
resource "aws_security_group" "allow_http" {
  name        = "allow_http"
  description = "Allow HTTP SSH inbound traffic"
  vpc_id      = "vpc-d4ebf6bc"

  ingress {
    description = "HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [ "0.0.0.0/0" ]
  }
  
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }


  tags = {
    Name = "my_http"
  }
}
```

#### Step 3 "Launching the Instance".
In the third and the most critical step as all the steps above revolves around this step. The instance which we are creating here is used to deploy webserver and nearly all other tasks are also done here. The isntance is launched using the keys and security groups created previously.
```
resource "aws_instance" "myweb" {
	ami		= "ami-005956c5f0f757d37"
	instance_type	="t2.micro"
	key_name          = "abhishek"
  	security_groups   = [ "allow_http" ]

	 connection {
    	type        = "ssh"
    	user        = "ec2-user"
    	private_key = file("C:/Users/Abhishek/Downloads/abhishek.pem")
    	host        = "${aws_instance.myweb.public_ip}"
  	}
  
 	 provisioner "remote-exec" {
    	inline = [
      	"sudo yum install httpd  -y",
      	"sudo service httpd start",
      	"sudo service httpd enable"
    	]
 	 }

	tags = {
		Name = "Abhishekos"
	}
}

output "o3" {
	value = aws_instance.myweb.public_ip
}

output "o4" {
	value = aws_instance.myweb.availability_zone
}
```
#### Step 4 " Creating S3 bucket".
Next, I created an S3 bucket and also manipulated the terraform to save my bucket name in my local system inside my working repository. This is for the time when I destroy the infrastructure created by, it will ask for bucket name which I have made dynamic as we need a unique name for our bucket as S3 is a global service.
```
resource "aws_s3_bucket" "myuniquebucket1227" {
  bucket = "myuniquebucket1227" 
  acl    = "public-read"
  tags = {
    Name        = "uniquebucket1227" 
  }
  versioning {
	enabled =true
  }
}

resource "aws_s3_bucket_object" "s3object" {
  bucket = "${aws_s3_bucket.myuniquebucket1227.id}"
  key    = "1076883.jpg"
  source = "C:/Users/Abhishek/Downloads/1076883.jpg"
}
```
#### Step 5 "Cloud Front".
Creating Cloudfront distribution for S3 bucket in this step as we want to decrease the latency as much as we can through the CDN (Content Delivery Network). This in turns provide a different link to all S3 storage contents and will also help in reducing latency for the clients.
```
resource "aws_cloudfront_distribution" "imagecf" {
    origin {
        domain_name = "myuniquebucket1227.s3.amazonaws.com"
        origin_id = "S3-myuniquebucket1227"


        s3_origin_config {
      origin_access_identity = aws_cloudfront_origin_access_identity.origin_access_identity.cloudfront_access_identity_path
    }
  }
       
    enabled = true
      is_ipv6_enabled     = true

    default_cache_behavior {
        allowed_methods = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
        cached_methods = ["GET", "HEAD"]
        target_origin_id = "S3-myuniquebucket1227"


        # Forward all query strings, cookies and headers
        forwarded_values {
            query_string = false
        
            cookies {
               forward = "none"
            }
        }
        viewer_protocol_policy = "allow-all"
        min_ttl = 0
        default_ttl = 10
        max_ttl = 30
    }
    # Restricts who is able to access this content
    restrictions {
        geo_restriction {
            # type of restriction, blacklist, whitelist or none
            restriction_type = "none"
        }
    }


    # SSL certificate for the service.
    viewer_certificate {
        cloudfront_default_certificate = true
    }
}
```
#### Step 6 "EFS creation".
In this step we are creating an extra EFS (Elastic File System) volume and attaching this extra created volume to our instances so that it can be accessed by us from instance. 
``` 
resource “aws_efs_file_system” “efs_plus” {
depends_on = [aws_security_group.abhitf_sg, aws_instance.AbhiOs1]
creation_token = “efs”
tags = {
Name = “aniefs”
}
}
resource “aws_efs_mount_target” “mount_efs” {depends_on = [aws_efs_file_system.efs_plus]
file_system_id = aws_efs_file_system.efs_plus.id
subnet_id = aws_instance.Abhios.subnet_id
security_groups=[aws_security_group.anitf_sg.id]
}
resource “null_resource” “cluster” {
depends_on = [
aws_efs_file_system.efs_plus,
]
connection {
type = “ssh”
user = “ec2-user”
private_key = file("C:/Users/Abhishek/Downloads/abhi1234.pem")
host = aws_instance.Abhios.public_ip
}
provisioner “remote-exec” {
inline = [“sudo echo ${aws_efs_file_system.efs_plus.dns_name}:/var/www/html efs defaults._netdev 0 0>>sudo /etc/fstab”,
“sudo mount ${aws_efs_file_system.efs_plus.dns_name}:/var/www/html/*”,
“sudo rm -rf /var/www/html/*”,
“sudo git clone https://github.com/abiswah/AWS_2 /var/www/html “
   ]
  }
}
```
