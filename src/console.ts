export class ConsoleLine {
  private base = ''

  public writeBase(base: string) {
    this.base = base
    process.stdout.write(base)
  }

  public newline() {
    this.base = ''
    process.stdout.write('\n')
  }

  public update(...args: Array<string | number | boolean | null | undefined>) {
    process.stdout.cursorTo(this.base.length)
    process.stdout.write(args.join(' '))
    process.stdout.clearLine(1)
  }
}
