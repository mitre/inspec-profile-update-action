control 'SV-20679' do
  title 'Email backups must meet schedule and storage requirements.'
  desc 'Hardware failures or other (sometimes physical) disasters can cause data loss to active applications, and precipitate the need for expedient recovery.  Ensuring backups are conducted on an agreed schedule creates a timely copy from which to recover active systems. Storing backup contents at a separate physical location protects the backup data from site-specific physical disasters. Backup schedule and storage location are determined in accordance with the MAC category and confidentiality level of the system.'
  desc 'check', 'Access the EDSP for intended backup schedule and storage provisions. Review artifacts, such as job logs, file locations, access protections and procedures for offline files, and storage methods that demonstrate compliance to the intended schedule and log storage requirements. 

If email backups are conducted according to the EDSP, on schedule and are stored appropriately, this is not a finding.'
  desc 'fix', 'Document the email backup strategy in the EDSP and perform backups on the schedule that is documented.  Store the data as required.'
  impact 0.5
  ref 'DPMS Target E-mail Services Policy'
  tag check_id: 'C-22537r3_chk'
  tag severity: 'medium'
  tag gid: 'V-18883'
  tag rid: 'SV-20679r3_rule'
  tag stig_id: 'EMG3-007 EMail'
  tag gtitle: 'EMG3-007 Backups Interval and Storage Location'
  tag fix_id: 'F-19580r2_fix'
  tag 'documentable'
  tag responsibility: 'Other'
  tag ia_controls: 'CODB-2'
end
