class User < ActiveRecord::Base

  #
  # These scopes are used to allow the application to filter
  # out users that have been deleted
  #
  scope :active, -> { where(inactive: nil) }
  scope :deleted, -> { where(inactive: true) }

  def soft_delete
    # assuming you have deleted_at column added already
    update_attribute(:deleted_at, Time.current)
    update_attribute(:inactive, true)
  end

  # This is for simple_token_authentication:
  acts_as_token_authenticatable


  # Include default devise modules. Others available are:
  # :confirmable, :lockable and :omniauthable
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :trackable, :validatable,
         :timeoutable, :timeout_in => 15.seconds
  #attr_accessible :email, :password, :password_confirmation

  # TODO: Add an attribute to be used for authorization purposes

  # TODO: Add an attribute to be used for authentication_token expiration purposes (if we need it)

  # TODO: Add first name, last name, profile image URL

end
