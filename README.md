### Amazon AWIS

Fetch information from AWIS (Alexa Web Information Service).

**Currently only implemented for TrafficHistory Action.**

#### Install

In your gemfile:

```ruby
gem 'amazon-awis', github: 'contiamo/amazon-awis'
```

#### Example

```ruby
require 'amazon/awis'

request = Amazon::Awis.new(aws_access_key_id: [your developer token], aws_secret_key: [your secret access key])

# fetch data
res = request.get_info('yahoo.com')

# some common response object methods
res.success?   # return true if request was successful
res.data
```

Refer to Amazon AWIS documentation for more information on Amazon REST request parameters and XML output:
http://docs.aws.amazon.com/AlexaWebInfoService/latest/
