control 'SV-215181' do
  title 'The shipped /etc/security/mkuser.sys file on AIX must not be customized directly.'
  desc 'The "/etc/security/mkuser.sys" script customizes the new user account when a new user is created, or a user is logging into the system without a home directory. An improper "/etc/security/mkuser.sys" script increases the risk that non-privileged users may obtain elevated privileges.'
  desc 'check', %q(Use the "cat" command to show the content of "/etc/security/mkuser.sys" script:
# cat /etc/security/mkuser.sys

The cat command should display the following:
#   This file is no longer user customizable.  To have a customized mkuser.sys script
#   create a file /etc/security/mkuser.sys.custom and the /etc/security/mkuser.sys
#   will run this script instead of the original mkuser.sys script.

export PATH=/usr/bin:/usr/sbin:$PATH

#
# Check the number of arguments first
#
if [ $# -ne 4 ] 
then
 exit 1
fi

#
# If a customer mkuser.sys.custom script exists
# then execute it instead and exit passing all arguments
# and returning the return code from mkuser.sys.custom
#
if [ -x /etc/security/mkuser.sys.custom ]
then
 /etc/security/mkuser.sys.custom $*
 exit $?
fi

#
# Create the named directory if it does not already exist
# and set the file ownership and permission
#
if [ ! -d $1 ]
then
 last=$1
 
 while [ 1 ]
 do
  dir=`dirname $last`
  
  if [ -d $last ]
  then
   break
  elif [ -d $dir ]
  then
   mkdir -p $1
   chown -R bin:bin $last
   chmod -R 755 $last
   break
  else
   last=$dir
  fi
 done
 
 chgrp "$3" $1
 chown $2 $1
fi

#
# Copy the user's default .profile if it does not already
# exist and change the file ownership, etc.
#
if [ `basename $4` != "csh" ] && [ ! -f $1/.profile ]
then
 cp /etc/security/.profile $1/.profile
 chmod u+rwx,go-w $1/.profile
 chgrp "$3" $1/.profile
 chown $2 $1/.profile

else
   if [ `basename $4` = "csh" ] && [ ! -f $1/.login ] 
   then
 echo "#!/bin/csh" > "$1"/.login
 echo "set path = ( /usr/bin /etc /usr/sbin /usr/ucb \$HOME/bin /usr/bin/X11 /sbin . )" >> "$1"/.login
 echo "setenv MAIL \"/var/spool/mail/\$LOGNAME\"" >> "$1"/.login
 echo "setenv MAILMSG \"[YOU HAVE NEW MAIL]\"" >> "$1"/.login
 echo "if ( -f \"\$MAIL\" && ! -z \"\$MAIL\") then" >> "$1"/.login
        echo " echo \"\$MAILMSG\"" >> "$1"/.login
 echo "endif" >> "$1"/.login
 chmod u+rwx,go-w $1/.login
 chgrp "$3" $1/.login
 chown $2 $1/.login
   fi
fi

If the "cat" command shows the script as different than the content listed above, this is a finding.)
  desc 'fix', %q(Edit the script /etc/security/mkuser.sys to contain the following:
#   This file is no longer user customizable.  To have a customized mkuser.sys script
#   create a file /etc/security/mkuser.sys.custom and the /etc/security/mkuser.sys
#   will run this script instead of the original mkuser.sys script.

export PATH=/usr/bin:/usr/sbin:$PATH

#
# Check the number of arguments first
#
if [ $# -ne 4 ] 
then
 exit 1
fi

#
# If a customer mkuser.sys.custom script exists
# then execute it instead and exit passing all arguments
# and returning the return code from mkuser.sys.custom
#
if [ -x /etc/security/mkuser.sys.custom ]
then
 /etc/security/mkuser.sys.custom $*
 exit $?
fi

#
# Create the named directory if it does not already exist
# and set the file ownership and permission
#
if [ ! -d $1 ]
then
 last=$1
 
 while [ 1 ]
 do
  dir=`dirname $last`
  
  if [ -d $last ]
  then
   break
  elif [ -d $dir ]
  then
   mkdir -p $1
   chown -R bin:bin $last
   chmod -R 755 $last
   break
  else
   last=$dir
  fi
 done
 
 chgrp "$3" $1
 chown $2 $1
fi

#
# Copy the user's default .profile if it does not already
# exist and change the file ownership, etc.
#
if [ `basename $4` != "csh" ] && [ ! -f $1/.profile ]
then
 cp /etc/security/.profile $1/.profile
 chmod u+rwx,go-w $1/.profile
 chgrp "$3" $1/.profile
 chown $2 $1/.profile

else
   if [ `basename $4` = "csh" ] && [ ! -f $1/.login ] 
   then
 echo "#!/bin/csh" > "$1"/.login
 echo "set path = ( /usr/bin /etc /usr/sbin /usr/ucb \$HOME/bin /usr/bin/X11 /sbin . )" >> "$1"/.login
 echo "setenv MAIL \"/var/spool/mail/\$LOGNAME\"" >> "$1"/.login
 echo "setenv MAILMSG \"[YOU HAVE NEW MAIL]\"" >> "$1"/.login
 echo "if ( -f \"\$MAIL\" && ! -z \"\$MAIL\") then" >> "$1"/.login
        echo " echo \"\$MAILMSG\"" >> "$1"/.login
 echo "endif" >> "$1"/.login
 chmod u+rwx,go-w $1/.login
 chgrp "$3" $1/.login
 chown $2 $1/.login
   fi
fi)
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16379r293994_chk'
  tag severity: 'medium'
  tag gid: 'V-215181'
  tag rid: 'SV-215181r508663_rule'
  tag stig_id: 'AIX7-00-001015'
  tag gtitle: 'SRG-OS-000001-GPOS-00001'
  tag fix_id: 'F-16377r293995_fix'
  tag 'documentable'
  tag legacy: ['SV-101311', 'V-91211']
  tag cci: ['CCI-000015']
  tag nist: ['AC-2 (1)']
end
