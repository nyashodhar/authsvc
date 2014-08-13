class AddAuthenticationTokenToUsers < ActiveRecord::Migration
  def change
    add_column :users, :authentication_token, :string
    add_index :users, :authentication_token
  end
  def self.down
    raise ActiveRecord::IrreversibleMigration
  end
end
