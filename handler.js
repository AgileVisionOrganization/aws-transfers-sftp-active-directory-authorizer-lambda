const LDAP = require("ldapjs");

const client = LDAP.createClient({
  url: `ldap://${process.env.LDAP_DNS_NAME}:389`
});

const getSftpPolicy = username =>
  JSON.stringify({
    Role: process.env.SFTP_USER_ROLE_ARN,
    Policy:
      `{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowListingOfUserFolder",
                "Action": [
                    "s3:ListBucket"
                ],
                "Effect": "Allow",
                "Resource": [` +
      '"arn:aws:s3:::${transfer:HomeBucket}"' +
      `],
                "Condition": {
                    "StringLike": {
                        "s3:prefix": [` +
      '"${transfer:UserName}/*",' +
      '"${transfer:UserName}"' +
      `]
                    }
                }
            },
            {
                "Sid": "AWSTransferRequirements",
                "Effect": "Allow",
                "Action": [
                    "s3:ListAllMyBuckets",
                    "s3:GetBucketLocation"
                ],
                "Resource": "*"
            },
            {
                "Sid": "HomeDirObjectAccess",
                "Effect": "Allow",
                "Action": [
                    "s3:PutObject",
                    "s3:GetObject",
                    "s3:DeleteObjectVersion",
                    "s3:DeleteObject",
                    "s3:GetObjectVersion"
                ],` +
      '"Resource": "arn:aws:s3:::${transfer:HomeDirectory}*"' +
      `}
        ]
      }`,
    HomeDirectory: `/${process.env.BUCKET_ARN.substring("arn:aws:s3:::".length)}/${username}/`,
    HomeBucket: process.env.BUCKET_ARN.substring("arn:aws:s3:::".length)
  });

exports.authorize = async function(event) {
  return new Promise((resolve, reject) => {
    const username = event.pathParameters.user;
    const password = event.headers.Password;

    console.log(`Performing authentication for user ${username}`);

    client.bind(`${username}@${process.env.LDAP_DIRECTORY_NAME}`, password, err => {
      if (err) {
        reject(err);
      } else {
        const response = {
          headers: {
            "Access-Control-Allow-Origin": "*",
            "Content-Type": "application/json"
          },
          body: getSftpPolicy(username),
          statusCode: 200
        };
        resolve(response);
      }
    });
  });
};
