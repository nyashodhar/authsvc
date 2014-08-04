class ApplicationController < ActionController::Base

  # This is for simple_token_authentication
  acts_as_token_authentication_handler_for User

  # Prevent CSRF attacks by raising an exceptions Per-Yash-Will
  # For APIs, you may want to use :null_session instead.
  protect_from_forgery with: :exception

  rescue_from StandardError do |e|
    error(e)
  end

  rescue_from SyntaxError do |e|
    error(e)
  end

  def error(e)
    trace = e.backtrace[0,10].join("\n")
    logger.error "Custom error handler - Error: #{e.class.name} : #{e.message}, Trace: #{trace}\n"
    render :status => 500, :json => {:error => I18n.t("500response_internal_server_error")}.to_json
  end

end
