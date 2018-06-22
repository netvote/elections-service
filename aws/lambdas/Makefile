build:
	rm -f lambdas.zip
	zip -r lambdas.zip *

upload:
	aws s3 cp lambdas.zip s3://netvote-lambda-code/lambdas.zip

deploy_cast_vote:
	aws lambda update-function-code --function-name netvote-cast-vote --s3-bucket netvote-lambda-code --s3-key lambdas.zip
	aws lambda update-function-code --function-name private-cast-vote --s3-bucket netvote-lambda-code --s3-key lambdas.zip

deploy_create_election:
	aws lambda update-function-code --function-name netvote-create-election --s3-bucket netvote-lambda-code --s3-key lambdas.zip
	aws lambda update-function-code --function-name private-create-election --s3-bucket netvote-lambda-code --s3-key lambdas.zip

deploy: deploy_cast_vote deploy_create_election

publish: build upload deploy
