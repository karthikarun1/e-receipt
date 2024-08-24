for fname in subscription_management.py org_management.py  user_management.py permissions_management.py email_util.py
do
  fns=$(cat $fname|grep "def "|grep -v "def _")
  echo $fname
  echo $fns
done
