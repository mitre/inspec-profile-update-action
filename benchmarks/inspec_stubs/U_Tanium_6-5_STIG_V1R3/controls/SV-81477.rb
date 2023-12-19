control 'SV-81477' do
  title 'The Tanium Client - Set Action Lock must be set to OFF during maintenance window timeframes only.'
  desc 'Set Action Lock On will prevent any managed system from executing Tanium generated actions. This functionality is helpful when needing to eliminate systems from taking actions (e.g. patch scanning/installation, unmanaged asset scanning, updating, etc.), whether it is automatically scheduled upon install or manually scheduled. This functionality can also be used to help debug performance issues on a client if there is a fear that Tanium is running an action that could be causing a negative impact.

Setting Action Lock Off will ensure any Tanium generated actions are executed at the endpoint.'
  desc 'check', 'Using a web browser on a system that has connectivity to the Tanium Server, access the Tanium Server web user interface (UI) and log on with CAC.

In the “Home” tab, locate the Tanium Administration dashboard.

Click on “Client Configuration”.

The results will display two windows. One window will show "Clients that can take actions - Action Lock Off" and the other window will show "Clients that cannot take actions - Action Lock On".

If any systems are listed in the "Clients that cannot take actions - Action Lock Off" window and it is not an official maintenance window timeframe for those systems, this is a finding.'
  desc 'fix', 'Using a web browser on a system that has connectivity to the Tanium Server, access the Tanium Server web user interface (UI) and log on with CAC.

In the “Home” tab, locate the Tanium Administration dashboard. 

Click on “Client Configuration”.

The results will display two windows. One window will show "Clients that can take actions - Action Lock Off" and the other window will show "Clients that cannot take actions - Action Lock On".

In the windows displaying systems with Action Lock Off, highlight to select all systems displayed.

Right-click and choose "Deploy Action".'
  impact 0.5
  ref 'DPMS Target Tanium 6.5'
  tag check_id: 'C-67623r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66987'
  tag rid: 'SV-81477r1_rule'
  tag stig_id: 'TANS-CL-000009'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-73087r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
