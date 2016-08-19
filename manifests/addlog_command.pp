#Define a log-file to add to ossec
define ossec::addlog_command(
  $logtype = 'command',
  $logcommand,
  $commandalias,
  $agent_log_cmd = true,
  $logfrequency = '60',
) {
  require ossec::params
# Issue #30
  if $agent_log_cmd
  {
    $ossec_notify_cmd = Service[$ossec::params::agent_service]
  } else {
    $ossec_notify_cmd = Service[$ossec::params::server_service]
  }

  concat::fragment { "ossec.conf_21-${commandalias}":
    target  => $ossec::params::config_file,
    content => template('ossec/21_ossecLogfile_command.conf.erb'),
    order   => 21,
    notify  => $ossec_notify_cmd
  }

}
