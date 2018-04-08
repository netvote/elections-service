build:
	rm -f lambdas.zip
	zip -r lambdas.zip *

deploy:
	aws s3 cp lambdas.zip s3://netvote-lambdas/lambdas.zip
	aws lambda update-function-code --function-name netvote-cast-vote --s3-bucket netvote-lambdas --s3-key lambdas.zip

publish: build deploy