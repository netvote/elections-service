build:
	rm -f lambdas.zip
	zip -r lambdas.zip *

upload:
	aws s3 cp lambdas.zip s3://netvote-lambda-code/lambdas.zip

deploy:
	aws lambda update-function-code --function-name netvote-cast-vote --s3-bucket netvote-lambda-code --s3-key lambdas.zip
	aws lambda update-function-code --function-name netvote-create-election --s3-bucket netvote-lambda-code --s3-key lambdas.zip
	aws lambda update-function-code --function-name private-create-election --s3-bucket netvote-lambda-code --s3-key lambdas.zip

publish: build upload deploy
