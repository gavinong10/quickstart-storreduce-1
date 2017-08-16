python templates/storreduce-group-az.py 2 > templates/storreduce-group-az2.template
python templates/storreduce-group-az.py 3 > templates/storreduce-group-az3.template
python templates/storreduce-group-az.py 4 > templates/storreduce-group-az4.template
aws s3 sync . s3://gong-cf-templates
echo https://gong-cf-templates.s3.amazonaws.com/templates/storreduce-group-az2.template
echo https://gong-cf-templates.s3.amazonaws.com/templates/storreduce-group-az3.template
echo https://gong-cf-templates.s3.amazonaws.com/templates/storreduce-group-az4.template
echo https://gong-cf-templates.s3.amazonaws.com/templates/quickstart-storreduce-master.template