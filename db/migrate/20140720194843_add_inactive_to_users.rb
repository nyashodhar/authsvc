class AddInactiveToUsers < ActiveRecord::Migration
  def change
    add_column :users, :inactive, :boolean
  end
  def self.down
    raise ActiveRecord::IrreversibleMigration
  end
end
