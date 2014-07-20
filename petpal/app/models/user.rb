class User < ActiveRecord::Base

  def soft_delete
    # assuming you have deleted_at column added already
    update_attribute(:deleted_at, Time.current)
    update_attribute(:inactive, true)
  end

  # This is for simple_token_authentication:
  acts_as_token_authenticatable


  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable and :omniauthable
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :trackable, :validatable

  #attr_accessible :email, :password, :password_confirmation

  # TODO: Add an attribute to be used for authorization purposes

  # TODO: Add an attribute to be used for authentication_token expiration purposes (if we need it)

  # TODO: Add first name, last name, profile image URL

end
