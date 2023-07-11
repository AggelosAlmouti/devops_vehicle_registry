# devops_vehicle_registry
A simple app to keep track of your registred vehicles

Requirements:
devops_app_automation (https://github.com/AggelosAlmouti/devops_app_automation)
docker
ansible

Configuration:
in app.py put your email and password on hints, this email will be the sender of the email function of the app.
(recomended) place the automation folder in the same directory as your other files (app.py, instance etc.)
change the playbook deploy_docker_container to target the autmations inventory location and your ssh key that you will have to craete
  if you don't already have one.
from inside the playbook folder run ansible-playbook deploy_docker_container.yml
open browser on 127.0.0.2

Admin user should already be created: username: admin@registry.com pass: asdf1234
  if not create him with these credentials
