set -x
email=$1
flask make-superuser $email
