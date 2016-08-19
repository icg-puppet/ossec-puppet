#Define a log-file to add to ossec
define ossec::addlog_command(
  $logtype = 'command',
  $logcommand,
  $commandalias,
  $logfrequency = '60',
) {
  require ossec::params

  concat::fragment { "ossec.conf_21-${commandalias}":
    target  => $ossec::params::config_file,
    content => template('ossec/21_ossecLogfile_command.conf.erb'),
    order   => 21,
    notify  => Service[$ossec::params::server_service]
  }

}
