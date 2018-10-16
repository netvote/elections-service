build:
	rm -f lambdas.zip
	zip -r lambdas.zip *

upload:
	aws s3 cp lambdas.zip s3://netvote-lambda-code/lambdas.zip

mount:
	docker run -it -v $(CURDIR):/lambda --entrypoint=/bin/bash 8base/docker-amazonlinux-node

deploy_add_authid:
	aws lambda update-function-code --function-name election-add-authid --s3-bucket netvote-lambda-code --s3-key lambdas.zip
	aws lambda update-function-code --function-name election-publish-authids --s3-bucket netvote-lambda-code --s3-key lambdas.zip

deploy_audit_election:
	aws lambda update-function-code --function-name election-audit --s3-bucket netvote-lambda-code --s3-key lambdas.zip

deploy_cast_vote:
	aws lambda update-function-code --function-name election-cast-vote --s3-bucket netvote-lambda-code --s3-key lambdas.zip

deploy_create_election:
	aws lambda update-function-code --function-name election-create --s3-bucket netvote-lambda-code --s3-key lambdas.zip

deploy_activate_election:
	aws lambda update-function-code --function-name election-activate --s3-bucket netvote-lambda-code --s3-key lambdas.zip

deploy_reveal_key:
	aws lambda update-function-code --function-name election-reveal-key --s3-bucket netvote-lambda-code --s3-key lambdas.zip

deploy_close_election:
	aws lambda update-function-code --function-name election-close --s3-bucket netvote-lambda-code --s3-key lambdas.zip

deploy_tally_election:
	aws lambda update-function-code --function-name election-tally --s3-bucket netvote-lambda-code --s3-key lambdas.zip
	aws lambda update-function-code --function-name election-export --s3-bucket netvote-lambda-code --s3-key lambdas.zip

deploy_get_vote:
	aws lambda update-function-code --function-name election-lookup-vote --s3-bucket netvote-lambda-code --s3-key lambdas.zip

deploy_add_observation:
	aws lambda update-function-code --function-name private-add-observation --s3-bucket netvote-lambda-code --s3-key lambdas.zip
	aws lambda update-function-code --function-name netvote-add-observation --s3-bucket netvote-lambda-code --s3-key lambdas.zip

deploy_keep_alive:
	aws lambda update-function-code --function-name private-keep-alive --s3-bucket netvote-lambda-code --s3-key lambdas.zip

deploy: deploy_audit_election deploy_add_authid deploy_cast_vote deploy_create_election deploy_activate_election deploy_close_election deploy_tally_election deploy_get_vote deploy_add_observation deploy_reveal_key deploy_keep_alive

publish: build upload deploy
