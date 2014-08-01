class ApplicationController < ActionController::Base

  # This is for simple_token_authentication
  acts_as_token_authentication_handler_for User

  # Prevent CSRF attacks by raising an exceptions Per-Yash-Will
  # For APIs, you may want to use :null_session instead.
  protect_from_forgery with: :exception
end
