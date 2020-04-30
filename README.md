# Scanamabob

Scanamabob is a set of AWS-specific tools that aide in managing the security of AWS environments.

Scanamabob is currently in an alpha development state. As such, many expected features are missing or incomplete and there may be significant changes in the near future that may break any automations made around the current version. 

### Features

- Intelligent scanning of AWS environment for common security misconfigurations
- S3 auditor for identifying publicly exposed resources

## Configuration

Scanamabob uses the boto3 library to consume the AWS API. As such, Scanamabob is configured via the `aws` cli commands.

```
$ aws configure
AWS Access Key ID [****************ZXIh]: dXJ5eWIgZ3VyZXIh
AWS Secret Access Key [****************dHRm]: didxIHRocmZmIGxiaCBuY2NlcnB2bmdyIHJuZmdyZSBydHRm
Default region name [us-east-1]: 
Default output format [json]: 
```

## Basic operation

Runs like a standard python app, `-h` can help you find the small set of supported options.

```
Usage: scanamabob <command> [-h] [command-specific-arguments]

Scanamabob v0.0.1 - AWS Security Tooling

  s3audit  -  Identify publicly accessible S3 buckets and objects
  scan     -  Scan AWS environment for common security misconfigurations
```


### Testing

The infrastructure for testing is brought up and down by [Terraform](https://www.terraform.io).
Make sure you have that installed before running the tests.  Then do:

```
make infraup
make test
make infradown
```
