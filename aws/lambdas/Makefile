build:
	rm -f lambdas.zip
	zip -r lambdas.zip *

upload:
	aws s3 cp lambdas.zip s3://netvote-lambda-code/lambdas.zip

mount:
	docker run -it -v $(CURDIR):/lambda --entrypoint=/bin/bash 8base/docker-amazonlinux-node

deploy_cast_vote:
	aws lambda update-function-code --function-name netvote-cast-vote --s3-bucket netvote-lambda-code --s3-key lambdas.zip
	aws lambda update-function-code --function-name private-cast-vote --s3-bucket netvote-lambda-code --s3-key lambdas.zip

deploy_create_election:
	aws lambda update-function-code --function-name netvote-create-election --s3-bucket netvote-lambda-code --s3-key lambdas.zip
	aws lambda update-function-code --function-name private-create-election --s3-bucket netvote-lambda-code --s3-key lambdas.zip

deploy_activate_election:
	aws lambda update-function-code --function-name netvote-activate-election --s3-bucket netvote-lambda-code --s3-key lambdas.zip
	aws lambda update-function-code --function-name private-activate-election --s3-bucket netvote-lambda-code --s3-key lambdas.zip

deploy_reveal_key:
	aws lambda update-function-code --function-name netvote-reveal-key --s3-bucket netvote-lambda-code --s3-key lambdas.zip
	aws lambda update-function-code --function-name private-reveal-key --s3-bucket netvote-lambda-code --s3-key lambdas.zip

deploy_close_election:
	aws lambda update-function-code --function-name netvote-close-election --s3-bucket netvote-lambda-code --s3-key lambdas.zip
	aws lambda update-function-code --function-name private-close-election --s3-bucket netvote-lambda-code --s3-key lambdas.zip

deploy_tally_election:
	aws lambda update-function-code --function-name netvote-tally-election --s3-bucket netvote-lambda-code --s3-key lambdas.zip
	aws lambda update-function-code --function-name private-tally-election --s3-bucket netvote-lambda-code --s3-key lambdas.zip

deploy_get_vote:
	aws lambda update-function-code --function-name netvote-get-vote --s3-bucket netvote-lambda-code --s3-key lambdas.zip
	aws lambda update-function-code --function-name private-get-vote --s3-bucket netvote-lambda-code --s3-key lambdas.zip

deploy_add_observation:
	aws lambda update-function-code --function-name private-add-observation --s3-bucket netvote-lambda-code --s3-key lambdas.zip
	aws lambda update-function-code --function-name netvote-add-observation --s3-bucket netvote-lambda-code --s3-key lambdas.zip

deploy: deploy_cast_vote deploy_create_election deploy_activate_election deploy_close_election deploy_tally_election deploy_get_vote deploy_add_observation deploy_reveal_key

publish: build upload deploy
