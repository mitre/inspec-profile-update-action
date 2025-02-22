control 'SV-24652' do
  title 'Unapproved inactive or expired database accounts should not be found on the database.'
  desc 'Unused or expired DBMS accounts provide a means for undetected, unauthorized access to the database.'
  desc 'check', 'Review procedures and implementation for monitoring the DBMS for account expiration and account inactivity.

Verify implemented procedures are in place to address expired/locked accounts not required for system/application operation are authorized to remain and are documented.

Verify implemented procedures are in place to address accounts that are unlocked and have been inactive in excess of 30 days are authorized to remain unlocked.

Verify implemented procedures are in place to address unauthorized, inactive accounts after 30 days are expired and locked.

Verify implemented procedures are in place to address expired/locked accounts that are not authorized to remain are dropped/removed/deleted.

A finding for this check would be based on insufficient documentation and implemented procedures for monitoring DBMS accounts.'
  desc 'fix', 'Develop, document and implement procedures to monitor database accounts for inactivity and account expiration.

Investigate and re-authorize or delete [if appropriate] any accounts that are expired or have been inactive for more than 30 days.

Where appropriate, protect authorized expired or inactive accounts by disabling them or applying some other similar protection.

NOTE:  Password and account requirements have changed for DoD since this STIG requirement was published.'
  impact 0.5
  ref 'DPMS Target Oracle Databases 11g'
  tag check_id: 'C-29176r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15130'
  tag rid: 'SV-24652r1_rule'
  tag stig_id: 'DG0074-ORACLE11'
  tag gtitle: 'DBMS inactive accounts'
  tag fix_id: 'F-26187r1_fix'
  tag 'documentable'
  tag responsibility: 'Database Administrator'
end
