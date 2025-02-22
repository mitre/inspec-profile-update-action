control 'SV-218100' do
  title 'The mail system must forward all mail for root to one or more system administrators.'
  desc 'A number of system services utilize email messages sent to the root user to notify system administrators of active or impending issues.  These messages must be forwarded to at least one monitored email address.'
  desc 'check', 'Find the list of alias maps used by the Postfix mail server:

# postconf alias_maps

Query the Postfix alias maps for an alias for "root":

# postmap -q root hash:/etc/aliases

If there are no aliases configured for root that forward to a monitored email address, this is a finding.'
  desc 'fix', 'Set up an alias for root that forwards to a monitored email address:

# echo "root: <system.administrator>@mail.mil" >> /etc/aliases
# newaliases'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19581r377315_chk'
  tag severity: 'medium'
  tag gid: 'V-218100'
  tag rid: 'SV-218100r603264_rule'
  tag stig_id: 'RHEL-06-000521'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-19579r377316_fix'
  tag 'documentable'
  tag legacy: ['SV-50246', 'V-38446']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
