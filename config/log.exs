import Config

config :emqx, :logger,
    [{:handler,:default,:logger_std_h, 
        %{:config => %{:type => :standard_io}, 
          :formatter => {:emqx_logger_formatter,  %{:template => [:time,' [',:level,'] ', 
            {:client_id,[{:peername,[:client_id,'@',:peername,' '],[:client_id,' ']}],[{:peername,[:peername,' '],[]}]}, 
            :msg,'\n']}}, 
          :level => :error}},
     {:handler,:file,:logger_disk_log_h,
        %{:config => %{ :file => 'log/emqx.log', :max_no_bytes => 10485760, :max_no_files => 5,  :type => :wrap},
          :filesync_repeat_interval => :no_repeat,
          :formatter => {:emqx_logger_formatter,  %{:template => [:time,' [',:level,'] ',
            {:client_id,[{:peername,[:client_id,'@',:peername,' '],[:client_id,' ']}],[{:peername,[:peername,' '],[]}]},
            :msg,'\n']}},
          :level => :error
    }}]
