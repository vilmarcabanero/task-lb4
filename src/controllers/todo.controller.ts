import {authenticate} from '@loopback/authentication';
import {Count, Filter, repository} from '@loopback/repository';
import {del, get, param, patch, post, requestBody} from '@loopback/rest';
import {Todo} from '../models';
import {TodoRepository} from '../repositories';
import {UserRepository} from '@loopback/authentication-jwt';
import {SecurityBindings, UserProfile} from '@loopback/security';
import {inject} from '@loopback/core';
@authenticate('jwt')
export class TodoController {
  constructor(
    @repository(TodoRepository)
    public todoRepository: TodoRepository,
    @repository(UserRepository) protected userRepository: UserRepository,
    @inject(SecurityBindings.USER, {optional: true})
    public user: UserProfile,
  ) {}

  @get('/todos')
  async getAllTodos(
    @param.filter(Todo) filter?: Filter<Todo>,
  ): Promise<Todo[]> {
    return this.todoRepository.find(filter);
  }

  @get('/todos/active')
  async getActiveTodos(): Promise<Todo[]> {
    return this.todoRepository.getActiveTodos(this.user.id);
  }

  @get('/todos/complete')
  async getCompleteTodos(): Promise<Todo[]> {
    return this.todoRepository.getCompleteTodos(this.user.id);
  }

  @get('/todos/{id}')
  async getTodo(@param.path.string('id') id: string): Promise<Todo> {
    return this.todoRepository.findById(id);
  }

  @post('/todos')
  async createTodo(@requestBody() todo: {
    task: string,
    userId: string,
  }): Promise<object> {
    return this.todoRepository.create({task: todo.task, userId: this.user.id});
  }

  @patch('/todos/{id}')
  async updateTodo(
    @param.path.string('id') id: string,
    @requestBody() todo: {task: string},
  ): Promise<void> {
    await this.todoRepository.updateTodo(id, todo.task);
  }

  @patch('/todos/archive')
  async archiveCompleteTodolist(): Promise<Count> {
    return this.todoRepository.archiveCompleteTodolist(this.user.id);
  }

  @patch('/todos/complete/{id}')
  async makeComplete(@param.path.string('id') id: string): Promise<void> {
    await this.todoRepository.makeComplete(id);
  }

  @patch('/todos/incomplete/{id}')
  async makeIncomplete(@param.path.string('id') id: string): Promise<void> {
    await this.todoRepository.makeIncomplete(id);
  }

  @del('/todos/{id}')
  async deleteById(@param.path.string('id') id: string): Promise<void> {
    await this.todoRepository.deleteById(id);
  }
}
