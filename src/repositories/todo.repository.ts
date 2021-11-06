import {inject} from '@loopback/core';
import {DefaultCrudRepository, Where} from '@loopback/repository';
import {MongoDsDataSource} from '../datasources';
import {Todo, TodoRelations} from '../models';

export class TodoRepository extends DefaultCrudRepository<
  Todo,
  typeof Todo.prototype._id,
  TodoRelations
> {
  constructor(@inject('datasources.mongoDS') dataSource: MongoDsDataSource) {
    super(Todo, dataSource);
  }

  async getActiveTodos() {
    const filter = {
      where: {
        isActive: true,
      },
    };

    return this.find(filter);
  }

  async getCompleteTodos() {
    const filter = {
      where: {
        complete: true,
      },
    };

    return this.find(filter);
  }

  async makeComplete(id: string) {
    await this.updateById(id, {complete: true});
  }

  async makeIncomplete(id: string) {
    await this.updateById(id, {complete: false});
  }

  async archiveCompleteTodolist() {
    const where: Where<Todo> = {complete: true};

    return this.updateAll({isActive: false}, where);
  }

  async updateTodo(id: string, task: string) {
    return this.updateById(id, {task: task});
  }
}
