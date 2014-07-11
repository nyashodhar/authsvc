class PagesController < ApplicationController
  before_action :authenticate_user!
  
  def home
  	respond_to do |format|
      format.json { render json: 'Something To Cheer about' }
    end
  end
end
