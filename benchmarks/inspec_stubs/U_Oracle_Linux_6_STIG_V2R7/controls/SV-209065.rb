control 'SV-209065' do
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
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9318r357980_chk'
  tag severity: 'medium'
  tag gid: 'V-209065'
  tag rid: 'SV-209065r793786_rule'
  tag stig_id: 'OL6-00-000521'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-9318r357981_fix'
  tag 'documentable'
  tag legacy: ['V-50525', 'SV-64731']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
