using Microsoft.EntityFrameworkCore;
using SqliteWasmBlazor.Models.Models;

namespace SqliteWasmBlazor.Models;

public class NoteDbContext : DbContext
{
    public NoteDbContext(DbContextOptions<NoteDbContext> options) : base(options)
    {
    }

    public DbSet<Note> Notes { get; set; }
}
